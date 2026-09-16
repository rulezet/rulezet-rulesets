rule SUSP_Obfuscated_Powershell_reverse {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_reverse = "llehsrewop" nocase ascii wide
    $PowerShell_reverse = "llehSrewoP" nocase ascii wide
    $Powershell_reverse = "llehsrewoP" nocase ascii wide

  condition:
    any of them
}