rule TTP_XOR_MULT_DOSStub_63d9 {
  strings:
    $key_63d9 = { 37 b1 [2] 43 a9 [2] 04 ab [2] 43 ba [2] 0d b6 [2] 01 bc [2] 16 b7 [2] 0d f9 [2] 30 }

  condition:
    any of them
}