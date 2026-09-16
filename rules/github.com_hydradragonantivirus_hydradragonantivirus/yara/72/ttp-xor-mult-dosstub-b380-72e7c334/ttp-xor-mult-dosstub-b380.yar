rule TTP_XOR_MULT_DOSStub_b380 {
  strings:
    $key_b380 = { e7 e8 [2] 93 f0 [2] d4 f2 [2] 93 e3 [2] dd ef [2] d1 e5 [2] c6 ee [2] dd a0 [2] e0 }

  condition:
    any of them
}