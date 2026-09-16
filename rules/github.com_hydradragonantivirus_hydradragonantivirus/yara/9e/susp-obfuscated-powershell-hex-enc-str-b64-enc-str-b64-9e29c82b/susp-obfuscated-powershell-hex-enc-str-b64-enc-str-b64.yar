rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_b64_enc_str_b64 = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide
    $PowerShell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" base64 base64wide
    $Powershell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide

  condition:
    any of them
}