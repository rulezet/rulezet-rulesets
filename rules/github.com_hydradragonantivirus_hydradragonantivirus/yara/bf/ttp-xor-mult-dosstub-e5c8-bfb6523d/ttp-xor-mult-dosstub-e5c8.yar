rule TTP_XOR_MULT_DOSStub_e5c8 {
  strings:
    $key_e5c8 = { b1 a0 [2] c5 b8 [2] 82 ba [2] c5 ab [2] 8b a7 [2] 87 ad [2] 90 a6 [2] 8b e8 [2] b6 }

  condition:
    any of them
}