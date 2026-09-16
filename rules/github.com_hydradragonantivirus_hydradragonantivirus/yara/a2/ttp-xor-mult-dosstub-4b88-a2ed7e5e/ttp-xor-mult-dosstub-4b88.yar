rule TTP_XOR_MULT_DOSStub_4b88 {
  strings:
    $key_4b88 = { 1f e0 [2] 6b f8 [2] 2c fa [2] 6b eb [2] 25 e7 [2] 29 ed [2] 3e e6 [2] 25 a8 [2] 18 }

  condition:
    any of them
}