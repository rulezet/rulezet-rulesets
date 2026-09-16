rule sig_20160812_79e1e93f337dffc31564fdd0daa96711 {
  meta:
    description = "datamaliciousorder - file 20160812_79e1e93f337dffc31564fdd0daa96711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "957c6ede72774b927648ea1d6e753a0d34b5356be07dd7f0d5a88d91789f88f5"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -windowsty^le hi^dden (New-Object Sys" ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -windowsty^le hi^dden (New-Object Sys" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}