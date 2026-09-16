rule TTP_XOR_MULT_DOSStub_1888 {
  strings:
    $key_1888 = { 4c e0 [2] 38 f8 [2] 7f fa [2] 38 eb [2] 76 e7 [2] 7a ed [2] 6d e6 [2] 76 a8 [2] 4b }

  condition:
    any of them
}