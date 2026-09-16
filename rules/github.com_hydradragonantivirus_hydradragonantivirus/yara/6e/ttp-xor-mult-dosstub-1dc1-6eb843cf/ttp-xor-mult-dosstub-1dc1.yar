rule TTP_XOR_MULT_DOSStub_1dc1 {
  strings:
    $key_1dc1 = { 49 a9 [2] 3d b1 [2] 7a b3 [2] 3d a2 [2] 73 ae [2] 7f a4 [2] 68 af [2] 73 e1 [2] 4e }

  condition:
    any of them
}