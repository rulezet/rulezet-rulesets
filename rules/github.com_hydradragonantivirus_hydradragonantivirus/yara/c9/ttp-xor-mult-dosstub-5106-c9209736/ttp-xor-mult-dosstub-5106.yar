rule TTP_XOR_MULT_DOSStub_5106 {
  strings:
    $key_5106 = { 05 6e [2] 71 76 [2] 36 74 [2] 71 65 [2] 3f 69 [2] 33 63 [2] 24 68 [2] 3f 26 [2] 02 }

  condition:
    any of them
}