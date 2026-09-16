rule TTP_XOR_MULT_DOSStub_1dc7 {
  strings:
    $key_1dc7 = { 49 af [2] 3d b7 [2] 7a b5 [2] 3d a4 [2] 73 a8 [2] 7f a2 [2] 68 a9 [2] 73 e7 [2] 4e }

  condition:
    any of them
}