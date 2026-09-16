rule TTP_XOR_MULT_DOSStub_3888 {
  strings:
    $key_3888 = { 6c e0 [2] 18 f8 [2] 5f fa [2] 18 eb [2] 56 e7 [2] 5a ed [2] 4d e6 [2] 56 a8 [2] 6b }

  condition:
    any of them
}