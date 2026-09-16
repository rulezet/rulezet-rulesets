rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_hex_enc_str_reversed = "16c6c696a7f6d4" nocase ascii wide

  condition:
    all of them
}