rule TTP_XOR_MULT_DOSStub_e688 {
  strings:
    $key_e688 = { b2 e0 [2] c6 f8 [2] 81 fa [2] c6 eb [2] 88 e7 [2] 84 ed [2] 93 e6 [2] 88 a8 [2] b5 }

  condition:
    any of them
}