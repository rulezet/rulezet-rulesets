rule SUSP_Obfuscated_Powershell_double_hex_enc_str_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_double_hex_enc_str_b64 = "3730366637373635373237333638363536633663" base64 base64wide
    $PowerShell_double_hex_enc_str_b64 = "3530366637373635373235333638363536633663" base64 base64wide
    $Powershell_double_hex_enc_str_b64 = "3530366637373635373237333638363536633663" base64 base64wide

  condition:
    any of them
}