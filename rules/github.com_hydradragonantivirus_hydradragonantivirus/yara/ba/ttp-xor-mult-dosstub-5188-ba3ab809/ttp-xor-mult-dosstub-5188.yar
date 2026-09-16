rule TTP_XOR_MULT_DOSStub_5188 {
  strings:
    $key_5188 = { 05 e0 [2] 71 f8 [2] 36 fa [2] 71 eb [2] 3f e7 [2] 33 ed [2] 24 e6 [2] 3f a8 [2] 02 }

  condition:
    any of them
}