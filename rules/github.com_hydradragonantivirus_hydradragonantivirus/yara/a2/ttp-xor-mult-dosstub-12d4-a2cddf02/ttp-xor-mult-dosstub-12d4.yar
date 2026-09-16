rule TTP_XOR_MULT_DOSStub_12d4 {
  strings:
    $key_12d4 = { 46 bc [2] 32 a4 [2] 75 a6 [2] 32 b7 [2] 7c bb [2] 70 b1 [2] 67 ba [2] 7c f4 [2] 41 }

  condition:
    any of them
}