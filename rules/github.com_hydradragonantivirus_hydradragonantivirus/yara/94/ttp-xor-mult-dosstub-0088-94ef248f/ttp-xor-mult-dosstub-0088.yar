rule TTP_XOR_MULT_DOSStub_0088 {
  strings:
    $key_0088 = { 54 e0 [2] 20 f8 [2] 67 fa [2] 20 eb [2] 6e e7 [2] 62 ed [2] 75 e6 [2] 6e a8 [2] 53 }

  condition:
    any of them
}