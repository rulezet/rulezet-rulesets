rule TTP_XOR_MULT_DOSStub_51c7 {
  strings:
    $key_51c7 = { 05 af [2] 71 b7 [2] 36 b5 [2] 71 a4 [2] 3f a8 [2] 33 a2 [2] 24 a9 [2] 3f e7 [2] 02 }

  condition:
    any of them
}