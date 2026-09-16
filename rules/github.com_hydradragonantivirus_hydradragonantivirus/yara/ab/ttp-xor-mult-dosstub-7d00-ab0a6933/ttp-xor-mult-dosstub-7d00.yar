rule TTP_XOR_MULT_DOSStub_7d00 {
  strings:
    $key_7d00 = { 29 68 [2] 5d 70 [2] 1a 72 [2] 5d 63 [2] 13 6f [2] 1f 65 [2] 08 6e [2] 13 20 [2] 2e }

  condition:
    any of them
}