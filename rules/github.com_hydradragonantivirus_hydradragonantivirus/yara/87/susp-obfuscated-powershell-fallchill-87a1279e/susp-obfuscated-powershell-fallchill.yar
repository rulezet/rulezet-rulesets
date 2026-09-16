rule SUSP_Obfuscated_Powershell_fallchill {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_fallchill = "kldvihsvoo" nocase ascii wide
    $PowerShell_fallchill = "PldviSsvoo" nocase ascii wide
    $Powershell_fallchill = "Pldvihsvoo" nocase ascii wide

  condition:
    any of them
}