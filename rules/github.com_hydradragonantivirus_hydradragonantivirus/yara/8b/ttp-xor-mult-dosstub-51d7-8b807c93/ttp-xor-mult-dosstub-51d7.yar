rule TTP_XOR_MULT_DOSStub_51d7 {
  strings:
    $key_51d7 = { 05 bf [2] 71 a7 [2] 36 a5 [2] 71 b4 [2] 3f b8 [2] 33 b2 [2] 24 b9 [2] 3f f7 [2] 02 }

  condition:
    any of them
}