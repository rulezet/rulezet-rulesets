rule TTP_XOR_MULT_DOSStub_e5d0 {
  strings:
    $key_e5d0 = { b1 b8 [2] c5 a0 [2] 82 a2 [2] c5 b3 [2] 8b bf [2] 87 b5 [2] 90 be [2] 8b f0 [2] b6 }

  condition:
    any of them
}