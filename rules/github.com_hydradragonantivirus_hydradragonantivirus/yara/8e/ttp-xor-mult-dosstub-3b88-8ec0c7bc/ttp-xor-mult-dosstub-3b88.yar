rule TTP_XOR_MULT_DOSStub_3b88 {
  strings:
    $key_3b88 = { 6f e0 [2] 1b f8 [2] 5c fa [2] 1b eb [2] 55 e7 [2] 59 ed [2] 4e e6 [2] 55 a8 [2] 68 }

  condition:
    any of them
}