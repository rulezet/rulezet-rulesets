rule TTP_XOR_MULT_DOSStub_7c06 {
  strings:
    $key_7c06 = { 28 6e [2] 5c 76 [2] 1b 74 [2] 5c 65 [2] 12 69 [2] 1e 63 [2] 09 68 [2] 12 26 [2] 2f }

  condition:
    any of them
}