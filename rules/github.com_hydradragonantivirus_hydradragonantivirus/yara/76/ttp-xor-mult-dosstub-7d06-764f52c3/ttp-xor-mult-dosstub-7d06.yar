rule TTP_XOR_MULT_DOSStub_7d06 {
  strings:
    $key_7d06 = { 29 6e [2] 5d 76 [2] 1a 74 [2] 5d 65 [2] 13 69 [2] 1f 63 [2] 08 68 [2] 13 26 [2] 2e }

  condition:
    any of them
}