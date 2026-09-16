rule TTP_XOR_MULT_DOSStub_e685 {
  strings:
    $key_e685 = { b2 ed [2] c6 f5 [2] 81 f7 [2] c6 e6 [2] 88 ea [2] 84 e0 [2] 93 eb [2] 88 a5 [2] b5 }

  condition:
    any of them
}