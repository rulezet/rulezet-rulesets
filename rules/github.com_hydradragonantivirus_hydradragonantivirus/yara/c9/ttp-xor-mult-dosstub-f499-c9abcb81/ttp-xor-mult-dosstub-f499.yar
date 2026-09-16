rule TTP_XOR_MULT_DOSStub_f499 {
  strings:
    $key_f499 = { a0 f1 [2] d4 e9 [2] 93 eb [2] d4 fa [2] 9a f6 [2] 96 fc [2] 81 f7 [2] 9a b9 [2] a7 }

  condition:
    any of them
}