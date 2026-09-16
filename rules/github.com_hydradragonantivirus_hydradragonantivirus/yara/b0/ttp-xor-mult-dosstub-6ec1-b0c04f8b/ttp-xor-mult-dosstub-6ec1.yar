rule TTP_XOR_MULT_DOSStub_6ec1 {
  strings:
    $key_6ec1 = { 3a a9 [2] 4e b1 [2] 09 b3 [2] 4e a2 [2] 00 ae [2] 0c a4 [2] 1b af [2] 00 e1 [2] 3d }

  condition:
    any of them
}