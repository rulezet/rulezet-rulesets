rule TTP_XOR_MULT_DOSStub_28c7 {
  strings:
    $key_28c7 = { 7c af [2] 08 b7 [2] 4f b5 [2] 08 a4 [2] 46 a8 [2] 4a a2 [2] 5d a9 [2] 46 e7 [2] 7b }

  condition:
    any of them
}