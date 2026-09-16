rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_hex_enc_str_b64_enc_str = "NGQ2ZjdhNjk2YzZjNjE=" nocase ascii wide

  condition:
    all of them
}