rule TTP_XOR_MULT_DOSStub_1188 {
  strings:
    $key_1188 = { 45 e0 [2] 31 f8 [2] 76 fa [2] 31 eb [2] 7f e7 [2] 73 ed [2] 64 e6 [2] 7f a8 [2] 42 }

  condition:
    any of them
}