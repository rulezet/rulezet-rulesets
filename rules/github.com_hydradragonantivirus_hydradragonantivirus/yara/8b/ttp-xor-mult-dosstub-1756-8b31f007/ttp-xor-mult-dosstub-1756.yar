rule TTP_XOR_MULT_DOSStub_1756 {
  strings:
    $key_1756 = { 43 3e [2] 37 26 [2] 70 24 [2] 37 35 [2] 79 39 [2] 75 33 [2] 62 38 [2] 79 76 [2] 44 }

  condition:
    any of them
}