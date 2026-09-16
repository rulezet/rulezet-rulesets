rule TTP_XOR_MULT_DOSStub_5a56 {
  strings:
    $key_5a56 = { 0e 3e [2] 7a 26 [2] 3d 24 [2] 7a 35 [2] 34 39 [2] 38 33 [2] 2f 38 [2] 34 76 [2] 09 }

  condition:
    any of them
}