rule SUSP_Obfuscated_Powershell_decimal {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_decimal = "112 111 119 101 114 115 104 101 108 108" nocase ascii wide
    $PowerShell_decimal = "80 111 119 101 114 83 104 101 108 108" nocase ascii wide
    $Powershell_decimal = "80 111 119 101 114 115 104 101 108 108" nocase ascii wide

  condition:
    any of them
}