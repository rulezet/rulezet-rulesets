rule sig_20160810_e82fda6d361c06f4e6c3bf1f6d14930a {
  meta:
    description = "datamaliciousorder - file 20160810_e82fda6d361c06f4e6c3bf1f6d14930a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cd54af3287c3a41a3ac484fa5931a705e86d9cf16ecd7308341a6e85fd5f2ed"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c powershell.exe -ExecutionPolicy bypass -noprofile -windowstyle hidden (New-Object System." ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c powershell.exe -ExecutionPolicy bypass -noprofile -windowstyle hidden (New-Object System." ascii
    $s3 = "cess '%APPDATA%.exe'\", \"\", \"open\", 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}