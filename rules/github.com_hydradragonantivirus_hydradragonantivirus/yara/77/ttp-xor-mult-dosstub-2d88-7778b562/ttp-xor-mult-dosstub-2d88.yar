rule TTP_XOR_MULT_DOSStub_2d88 {
  strings:
    $key_2d88 = { 79 e0 [2] 0d f8 [2] 4a fa [2] 0d eb [2] 43 e7 [2] 4f ed [2] 58 e6 [2] 43 a8 [2] 7e }

  condition:
    any of them
}