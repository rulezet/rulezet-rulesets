rule TTP_XOR_MULT_DOSStub_e2d9 {
  strings:
    $key_e2d9 = { b6 b1 [2] c2 a9 [2] 85 ab [2] c2 ba [2] 8c b6 [2] 80 bc [2] 97 b7 [2] 8c f9 [2] b1 }

  condition:
    any of them
}