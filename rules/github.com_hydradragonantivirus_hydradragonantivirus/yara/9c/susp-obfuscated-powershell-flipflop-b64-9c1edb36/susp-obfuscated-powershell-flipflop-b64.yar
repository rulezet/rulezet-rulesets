rule SUSP_Obfuscated_Powershell_flipflop_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_flipflop_b64 = "opewsrehll" base64 base64wide
    $PowerShell_flipflop_b64 = "oPewSrehll" base64 base64wide
    $Powershell_flipflop_b64 = "oPewsrehll" base64 base64wide

  condition:
    any of them
}