rule TTP_XOR_MULT_DOSStub_70c7 {
  strings:
    $key_70c7 = { 24 af [2] 50 b7 [2] 17 b5 [2] 50 a4 [2] 1e a8 [2] 12 a2 [2] 05 a9 [2] 1e e7 [2] 23 }

  condition:
    any of them
}