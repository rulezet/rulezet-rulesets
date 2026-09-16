rule TTP_XOR_MULT_DOSStub_5185 {
  strings:
    $key_5185 = { 05 ed [2] 71 f5 [2] 36 f7 [2] 71 e6 [2] 3f ea [2] 33 e0 [2] 24 eb [2] 3f a5 [2] 02 }

  condition:
    any of them
}