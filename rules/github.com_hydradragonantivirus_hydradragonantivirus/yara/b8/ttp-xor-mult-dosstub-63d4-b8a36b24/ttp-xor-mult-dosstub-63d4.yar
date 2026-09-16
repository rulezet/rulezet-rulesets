rule TTP_XOR_MULT_DOSStub_63d4 {
  strings:
    $key_63d4 = { 37 bc [2] 43 a4 [2] 04 a6 [2] 43 b7 [2] 0d bb [2] 01 b1 [2] 16 ba [2] 0d f4 [2] 30 }

  condition:
    any of them
}