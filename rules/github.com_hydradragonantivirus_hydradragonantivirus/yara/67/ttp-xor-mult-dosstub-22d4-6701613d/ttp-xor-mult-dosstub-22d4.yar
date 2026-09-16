rule TTP_XOR_MULT_DOSStub_22d4 {
  strings:
    $key_22d4 = { 76 bc [2] 02 a4 [2] 45 a6 [2] 02 b7 [2] 4c bb [2] 40 b1 [2] 57 ba [2] 4c f4 [2] 71 }

  condition:
    any of them
}