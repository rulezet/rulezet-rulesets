rule TTP_XOR_MULT_DOSStub_2888 {
  strings:
    $key_2888 = { 7c e0 [2] 08 f8 [2] 4f fa [2] 08 eb [2] 46 e7 [2] 4a ed [2] 5d e6 [2] 46 a8 [2] 7b }

  condition:
    any of them
}