rule TTP_XOR_MULT_DOSStub_e188 {
  strings:
    $key_e188 = { b5 e0 [2] c1 f8 [2] 86 fa [2] c1 eb [2] 8f e7 [2] 83 ed [2] 94 e6 [2] 8f a8 [2] b2 }

  condition:
    any of them
}