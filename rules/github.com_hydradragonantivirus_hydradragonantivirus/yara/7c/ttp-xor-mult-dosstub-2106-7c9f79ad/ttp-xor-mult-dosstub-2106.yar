rule TTP_XOR_MULT_DOSStub_2106 {
  strings:
    $key_2106 = { 75 6e [2] 01 76 [2] 46 74 [2] 01 65 [2] 4f 69 [2] 43 63 [2] 54 68 [2] 4f 26 [2] 72 }

  condition:
    any of them
}