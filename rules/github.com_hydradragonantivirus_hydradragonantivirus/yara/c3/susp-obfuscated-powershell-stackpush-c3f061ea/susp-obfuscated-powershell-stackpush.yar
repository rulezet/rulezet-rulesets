rule SUSP_Obfuscated_Powershell_stackpush {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_stackpush = "hllhrshehpowe" nocase ascii wide
    $PowerShell_stackpush = "hllhrShehPowe" nocase ascii wide
    $Powershell_stackpush = "hllhrshehPowe" nocase ascii wide

  condition:
    any of them
}