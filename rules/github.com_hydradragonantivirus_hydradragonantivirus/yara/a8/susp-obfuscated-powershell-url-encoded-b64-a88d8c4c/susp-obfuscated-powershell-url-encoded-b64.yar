rule SUSP_Obfuscated_Powershell_url_encoded_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_url_encoded_b64 = "70%6f%77%65%72%73%68%65%6c%6c" base64 base64wide
    $PowerShell_url_encoded_b64 = "50%6f%77%65%72%53%68%65%6c%6c" base64 base64wide
    $Powershell_url_encoded_b64 = "50%6f%77%65%72%73%68%65%6c%6c" base64 base64wide

  condition:
    any of them
}