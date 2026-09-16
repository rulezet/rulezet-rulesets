rule TTP_XOR_MULT_DOSStub_51d6 {
  strings:
    $key_51d6 = { 05 be [2] 71 a6 [2] 36 a4 [2] 71 b5 [2] 3f b9 [2] 33 b3 [2] 24 b8 [2] 3f f6 [2] 02 }

  condition:
    any of them
}