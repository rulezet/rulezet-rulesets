rule TTP_XOR_MULT_DOSStub_1b88 {
  strings:
    $key_1b88 = { 4f e0 [2] 3b f8 [2] 7c fa [2] 3b eb [2] 75 e7 [2] 79 ed [2] 6e e6 [2] 75 a8 [2] 48 }

  condition:
    any of them
}