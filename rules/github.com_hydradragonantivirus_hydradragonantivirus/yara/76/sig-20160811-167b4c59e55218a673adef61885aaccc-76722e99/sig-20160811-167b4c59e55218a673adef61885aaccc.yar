rule sig_20160811_167b4c59e55218a673adef61885aaccc {
  meta:
    description = "datamaliciousorder - file 20160811_167b4c59e55218a673adef61885aaccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1673a08a8d6efbd724359cbe197f3e572de83a4c133606583fef3c89ffa9f70a"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}