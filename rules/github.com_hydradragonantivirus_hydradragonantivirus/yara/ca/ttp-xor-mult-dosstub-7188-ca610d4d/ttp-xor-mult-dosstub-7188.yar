rule TTP_XOR_MULT_DOSStub_7188 {
  strings:
    $key_7188 = { 25 e0 [2] 51 f8 [2] 16 fa [2] 51 eb [2] 1f e7 [2] 13 ed [2] 04 e6 [2] 1f a8 [2] 22 }

  condition:
    any of them
}