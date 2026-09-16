rule TTP_XOR_MULT_DOSStub_4106 {
  strings:
    $key_4106 = { 15 6e [2] 61 76 [2] 26 74 [2] 61 65 [2] 2f 69 [2] 23 63 [2] 34 68 [2] 2f 26 [2] 12 }

  condition:
    any of them
}