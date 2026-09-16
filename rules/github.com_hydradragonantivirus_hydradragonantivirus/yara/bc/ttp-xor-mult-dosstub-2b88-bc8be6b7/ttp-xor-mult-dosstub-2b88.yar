rule TTP_XOR_MULT_DOSStub_2b88 {
  strings:
    $key_2b88 = { 7f e0 [2] 0b f8 [2] 4c fa [2] 0b eb [2] 45 e7 [2] 49 ed [2] 5e e6 [2] 45 a8 [2] 78 }

  condition:
    any of them
}