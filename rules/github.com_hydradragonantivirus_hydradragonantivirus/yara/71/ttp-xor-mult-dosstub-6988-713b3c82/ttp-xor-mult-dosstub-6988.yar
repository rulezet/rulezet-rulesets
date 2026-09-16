rule TTP_XOR_MULT_DOSStub_6988 {
  strings:
    $key_6988 = { 3d e0 [2] 49 f8 [2] 0e fa [2] 49 eb [2] 07 e7 [2] 0b ed [2] 1c e6 [2] 07 a8 [2] 3a }

  condition:
    any of them
}