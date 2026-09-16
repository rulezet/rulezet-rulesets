rule TTP_XOR_MULT_DOSStub_55d4 {
  strings:
    $key_55d4 = { 01 bc [2] 75 a4 [2] 32 a6 [2] 75 b7 [2] 3b bb [2] 37 b1 [2] 20 ba [2] 3b f4 [2] 06 }

  condition:
    any of them
}