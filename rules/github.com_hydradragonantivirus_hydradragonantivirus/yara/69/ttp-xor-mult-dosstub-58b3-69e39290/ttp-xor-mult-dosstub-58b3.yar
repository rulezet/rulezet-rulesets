rule TTP_XOR_MULT_DOSStub_58b3 {
  strings:
    $key_58b3 = { 0c db [2] 78 c3 [2] 3f c1 [2] 78 d0 [2] 36 dc [2] 3a d6 [2] 2d dd [2] 36 93 [2] 0b }

  condition:
    any of them
}