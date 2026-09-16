rule TTP_XOR_MULT_DOSStub_e4d9 {
  strings:
    $key_e4d9 = { b0 b1 [2] c4 a9 [2] 83 ab [2] c4 ba [2] 8a b6 [2] 86 bc [2] 91 b7 [2] 8a f9 [2] b7 }

  condition:
    any of them
}