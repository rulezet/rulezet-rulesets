rule SUSP_Obfuscated_Powershell_rot13_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_rot13_xor = "cbjrefuryy" xor(0x01-0xff) ascii wide
    $PowerShell_rot13_xor = "CbjreFuryy" xor(0x01-0xff) ascii wide
    $Powershell_rot13_xor = "Cbjrefuryy" xor(0x01-0xff) ascii wide

  condition:
    any of them
}