rule SUSP_Obfuscated_Powershell_stackpush_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_stackpush_b64 = "hllhrshehpowe" base64 base64wide
    $PowerShell_stackpush_b64 = "hllhrShehPowe" base64 base64wide
    $Powershell_stackpush_b64 = "hllhrshehPowe" base64 base64wide

  condition:
    any of them
}