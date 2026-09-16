rule TTP_XOR_MULT_DOSStub_4d88 {
  strings:
    $key_4d88 = { 19 e0 [2] 6d f8 [2] 2a fa [2] 6d eb [2] 23 e7 [2] 2f ed [2] 38 e6 [2] 23 a8 [2] 1e }

  condition:
    any of them
}