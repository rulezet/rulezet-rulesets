rule TTP_XOR_MULT_DOSStub_1356 {
  strings:
    $key_1356 = { 47 3e [2] 33 26 [2] 74 24 [2] 33 35 [2] 7d 39 [2] 71 33 [2] 66 38 [2] 7d 76 [2] 40 }

  condition:
    any of them
}