rule TTP_XOR_MULT_DOSStub_1d88 {
  strings:
    $key_1d88 = { 49 e0 [2] 3d f8 [2] 7a fa [2] 3d eb [2] 73 e7 [2] 7f ed [2] 68 e6 [2] 73 a8 [2] 4e }

  condition:
    any of them
}