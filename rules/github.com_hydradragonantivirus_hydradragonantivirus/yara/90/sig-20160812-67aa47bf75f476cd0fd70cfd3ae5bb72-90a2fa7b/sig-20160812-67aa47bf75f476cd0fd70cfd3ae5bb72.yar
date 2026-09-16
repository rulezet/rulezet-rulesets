rule sig_20160812_67aa47bf75f476cd0fd70cfd3ae5bb72 {
  meta:
    description = "datamaliciousorder - file 20160812_67aa47bf75f476cd0fd70cfd3ae5bb72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6edde33e34657e6e5ce3b4e707d51bd573e0d27abf75b09ae0eeddcf00aca02"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -windowsty^le hi^dden (New-Object Sys" ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -windowsty^le hi^dden (New-Object Sys" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}