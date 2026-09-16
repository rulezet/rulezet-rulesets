rule TTP_XOR_MULT_DOSStub_02d4 {
  strings:
    $key_02d4 = { 56 bc [2] 22 a4 [2] 65 a6 [2] 22 b7 [2] 6c bb [2] 60 b1 [2] 77 ba [2] 6c f4 [2] 51 }

  condition:
    any of them
}