rule TTP_XOR_MULT_DOSStub_e7d2 {
  strings:
    $key_e7d2 = { b3 ba [2] c7 a2 [2] 80 a0 [2] c7 b1 [2] 89 bd [2] 85 b7 [2] 92 bc [2] 89 f2 [2] b4 }

  condition:
    any of them
}