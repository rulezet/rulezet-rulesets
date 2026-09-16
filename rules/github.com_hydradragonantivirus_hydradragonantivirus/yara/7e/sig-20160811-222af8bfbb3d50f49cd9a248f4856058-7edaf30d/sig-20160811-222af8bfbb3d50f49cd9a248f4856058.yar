rule sig_20160811_222af8bfbb3d50f49cd9a248f4856058 {
  meta:
    description = "datamaliciousorder - file 20160811_222af8bfbb3d50f49cd9a248f4856058.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca36a37d59fd83384fd161e64941ad5f4dabb5831ad4f4c5a52b435562510fef"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}