rule TTP_XOR_MULT_DOSStub_7b06 {
  strings:
    $key_7b06 = { 2f 6e [2] 5b 76 [2] 1c 74 [2] 5b 65 [2] 15 69 [2] 19 63 [2] 0e 68 [2] 15 26 [2] 28 }

  condition:
    any of them
}