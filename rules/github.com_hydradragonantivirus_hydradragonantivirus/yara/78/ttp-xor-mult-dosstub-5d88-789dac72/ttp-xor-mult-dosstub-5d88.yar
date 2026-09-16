rule TTP_XOR_MULT_DOSStub_5d88 {
  strings:
    $key_5d88 = { 09 e0 [2] 7d f8 [2] 3a fa [2] 7d eb [2] 33 e7 [2] 3f ed [2] 28 e6 [2] 33 a8 [2] 0e }

  condition:
    any of them
}