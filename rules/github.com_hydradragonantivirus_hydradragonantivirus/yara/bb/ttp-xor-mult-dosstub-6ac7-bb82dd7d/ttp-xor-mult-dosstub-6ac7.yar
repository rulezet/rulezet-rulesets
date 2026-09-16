rule TTP_XOR_MULT_DOSStub_6ac7 {
  strings:
    $key_6ac7 = { 3e af [2] 4a b7 [2] 0d b5 [2] 4a a4 [2] 04 a8 [2] 08 a2 [2] 1f a9 [2] 04 e7 [2] 39 }

  condition:
    any of them
}