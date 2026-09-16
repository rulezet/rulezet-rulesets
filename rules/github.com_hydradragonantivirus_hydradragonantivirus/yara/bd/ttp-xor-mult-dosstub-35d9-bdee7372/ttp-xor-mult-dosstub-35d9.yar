rule TTP_XOR_MULT_DOSStub_35d9 {
  strings:
    $key_35d9 = { 61 b1 [2] 15 a9 [2] 52 ab [2] 15 ba [2] 5b b6 [2] 57 bc [2] 40 b7 [2] 5b f9 [2] 66 }

  condition:
    any of them
}