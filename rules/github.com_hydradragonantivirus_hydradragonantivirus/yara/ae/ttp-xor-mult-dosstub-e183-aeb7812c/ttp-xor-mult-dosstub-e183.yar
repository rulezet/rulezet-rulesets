rule TTP_XOR_MULT_DOSStub_e183 {
  strings:
    $key_e183 = { b5 eb [2] c1 f3 [2] 86 f1 [2] c1 e0 [2] 8f ec [2] 83 e6 [2] 94 ed [2] 8f a3 [2] b2 }

  condition:
    any of them
}