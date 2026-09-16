rule TTP_XOR_MULT_DOSStub_35d4 {
  strings:
    $key_35d4 = { 61 bc [2] 15 a4 [2] 52 a6 [2] 15 b7 [2] 5b bb [2] 57 b1 [2] 40 ba [2] 5b f4 [2] 66 }

  condition:
    any of them
}