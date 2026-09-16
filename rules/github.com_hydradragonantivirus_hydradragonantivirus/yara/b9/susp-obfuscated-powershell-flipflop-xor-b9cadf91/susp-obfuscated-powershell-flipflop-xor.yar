rule SUSP_Obfuscated_Powershell_flipflop_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_flipflop_xor = "opewsrehll" xor(0x01-0xff) ascii wide
    $PowerShell_flipflop_xor = "oPewSrehll" xor(0x01-0xff) ascii wide
    $Powershell_flipflop_xor = "oPewsrehll" xor(0x01-0xff) ascii wide

  condition:
    any of them
}