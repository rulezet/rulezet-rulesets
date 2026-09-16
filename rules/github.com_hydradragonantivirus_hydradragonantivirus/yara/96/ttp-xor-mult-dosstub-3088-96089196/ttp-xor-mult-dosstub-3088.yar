rule TTP_XOR_MULT_DOSStub_3088 {
  strings:
    $key_3088 = { 64 e0 [2] 10 f8 [2] 57 fa [2] 10 eb [2] 5e e7 [2] 52 ed [2] 45 e6 [2] 5e a8 [2] 63 }

  condition:
    any of them
}