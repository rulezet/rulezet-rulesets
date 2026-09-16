rule TTP_XOR_MULT_DOSStub_23d9 {
  strings:
    $key_23d9 = { 77 b1 [2] 03 a9 [2] 44 ab [2] 03 ba [2] 4d b6 [2] 41 bc [2] 56 b7 [2] 4d f9 [2] 70 }

  condition:
    any of them
}