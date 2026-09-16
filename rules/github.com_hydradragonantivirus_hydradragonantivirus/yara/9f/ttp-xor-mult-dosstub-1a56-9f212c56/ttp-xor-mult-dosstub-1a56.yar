rule TTP_XOR_MULT_DOSStub_1a56 {
  strings:
    $key_1a56 = { 4e 3e [2] 3a 26 [2] 7d 24 [2] 3a 35 [2] 74 39 [2] 78 33 [2] 6f 38 [2] 74 76 [2] 49 }

  condition:
    any of them
}