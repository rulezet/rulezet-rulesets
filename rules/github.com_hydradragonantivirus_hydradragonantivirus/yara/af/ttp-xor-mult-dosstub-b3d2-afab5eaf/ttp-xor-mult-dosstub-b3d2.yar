rule TTP_XOR_MULT_DOSStub_b3d2 {
  strings:
    $key_b3d2 = { e7 ba [2] 93 a2 [2] d4 a0 [2] 93 b1 [2] dd bd [2] d1 b7 [2] c6 bc [2] dd f2 [2] e0 }

  condition:
    any of them
}