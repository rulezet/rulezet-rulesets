rule TTP_XOR_MULT_DOSStub_e1d9 {
  strings:
    $key_e1d9 = { b5 b1 [2] c1 a9 [2] 86 ab [2] c1 ba [2] 8f b6 [2] 83 bc [2] 94 b7 [2] 8f f9 [2] b2 }

  condition:
    any of them
}