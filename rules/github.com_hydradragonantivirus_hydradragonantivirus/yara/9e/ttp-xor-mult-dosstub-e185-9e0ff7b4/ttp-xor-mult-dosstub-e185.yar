rule TTP_XOR_MULT_DOSStub_e185 {
  strings:
    $key_e185 = { b5 ed [2] c1 f5 [2] 86 f7 [2] c1 e6 [2] 8f ea [2] 83 e0 [2] 94 eb [2] 8f a5 [2] b2 }

  condition:
    any of them
}