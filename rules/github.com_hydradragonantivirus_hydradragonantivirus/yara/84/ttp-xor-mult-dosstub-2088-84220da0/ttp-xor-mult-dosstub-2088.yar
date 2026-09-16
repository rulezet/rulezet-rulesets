rule TTP_XOR_MULT_DOSStub_2088 {
  strings:
    $key_2088 = { 74 e0 [2] 00 f8 [2] 47 fa [2] 00 eb [2] 4e e7 [2] 42 ed [2] 55 e6 [2] 4e a8 [2] 73 }

  condition:
    any of them
}