rule TTP_XOR_MULT_DOSStub_ba88 {
  strings:
    $key_ba88 = { ee e0 [2] 9a f8 [2] dd fa [2] 9a eb [2] d4 e7 [2] d8 ed [2] cf e6 [2] d4 a8 [2] e9 }

  condition:
    any of them
}