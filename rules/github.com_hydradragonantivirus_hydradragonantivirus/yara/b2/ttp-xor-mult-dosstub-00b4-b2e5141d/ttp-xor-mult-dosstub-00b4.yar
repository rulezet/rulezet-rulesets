rule TTP_XOR_MULT_DOSStub_00b4 {
  strings:
    $key_00b4 = { 54 dc [2] 20 c4 [2] 67 c6 [2] 20 d7 [2] 6e db [2] 62 d1 [2] 75 da [2] 6e 94 [2] 53 }

  condition:
    any of them
}