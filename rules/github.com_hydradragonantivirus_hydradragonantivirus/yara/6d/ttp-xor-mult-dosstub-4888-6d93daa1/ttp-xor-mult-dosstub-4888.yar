rule TTP_XOR_MULT_DOSStub_4888 {
  strings:
    $key_4888 = { 1c e0 [2] 68 f8 [2] 2f fa [2] 68 eb [2] 26 e7 [2] 2a ed [2] 3d e6 [2] 26 a8 [2] 1b }

  condition:
    any of them
}