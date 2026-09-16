rule TTP_XOR_MULT_DOSStub_b2d9 {
  strings:
    $key_b2d9 = { e6 b1 [2] 92 a9 [2] d5 ab [2] 92 ba [2] dc b6 [2] d0 bc [2] c7 b7 [2] dc f9 [2] e1 }

  condition:
    any of them
}