rule SUSP_Obfuscated_Mozilla_decimal_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_decimal_xor = "77 111 122 105 108 108 97" xor(0x01-0xff) ascii wide

  condition:
    all of them
}