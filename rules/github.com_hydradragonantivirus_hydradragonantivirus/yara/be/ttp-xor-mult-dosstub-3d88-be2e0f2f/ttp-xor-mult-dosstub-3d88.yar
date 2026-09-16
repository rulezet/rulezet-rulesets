rule TTP_XOR_MULT_DOSStub_3d88 {
  strings:
    $key_3d88 = { 69 e0 [2] 1d f8 [2] 5a fa [2] 1d eb [2] 53 e7 [2] 5f ed [2] 48 e6 [2] 53 a8 [2] 6e }

  condition:
    any of them
}