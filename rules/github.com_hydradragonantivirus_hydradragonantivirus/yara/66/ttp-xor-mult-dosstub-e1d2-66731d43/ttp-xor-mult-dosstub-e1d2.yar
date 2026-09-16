rule TTP_XOR_MULT_DOSStub_e1d2 {
  strings:
    $key_e1d2 = { b5 ba [2] c1 a2 [2] 86 a0 [2] c1 b1 [2] 8f bd [2] 83 b7 [2] 94 bc [2] 8f f2 [2] b2 }

  condition:
    any of them
}