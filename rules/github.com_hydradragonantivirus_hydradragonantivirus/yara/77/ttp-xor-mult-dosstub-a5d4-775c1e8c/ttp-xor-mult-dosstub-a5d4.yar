rule TTP_XOR_MULT_DOSStub_a5d4 {
  strings:
    $key_a5d4 = { f1 bc [2] 85 a4 [2] c2 a6 [2] 85 b7 [2] cb bb [2] c7 b1 [2] d0 ba [2] cb f4 [2] f6 }

  condition:
    any of them
}