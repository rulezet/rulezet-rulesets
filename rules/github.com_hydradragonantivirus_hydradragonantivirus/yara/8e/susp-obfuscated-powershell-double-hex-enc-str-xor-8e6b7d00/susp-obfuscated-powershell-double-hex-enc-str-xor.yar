rule SUSP_Obfuscated_Powershell_double_hex_enc_str_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_double_hex_enc_str_xor = "3730366637373635373237333638363536633663" xor(0x01-0xff) ascii wide
    $PowerShell_double_hex_enc_str_xor = "3530366637373635373235333638363536633663" xor(0x01-0xff) ascii wide
    $Powershell_double_hex_enc_str_xor = "3530366637373635373237333638363536633663" xor(0x01-0xff) ascii wide

  condition:
    any of them
}