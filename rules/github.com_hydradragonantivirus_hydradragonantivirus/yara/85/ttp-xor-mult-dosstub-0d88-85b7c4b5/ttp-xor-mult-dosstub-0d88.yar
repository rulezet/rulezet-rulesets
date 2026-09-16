rule TTP_XOR_MULT_DOSStub_0d88 {
  strings:
    $key_0d88 = { 59 e0 [2] 2d f8 [2] 6a fa [2] 2d eb [2] 63 e7 [2] 6f ed [2] 78 e6 [2] 63 a8 [2] 5e }

  condition:
    any of them
}