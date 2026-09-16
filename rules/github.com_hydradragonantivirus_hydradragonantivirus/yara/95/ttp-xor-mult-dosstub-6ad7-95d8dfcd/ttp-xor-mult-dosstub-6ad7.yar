rule TTP_XOR_MULT_DOSStub_6ad7 {
  strings:
    $key_6ad7 = { 3e bf [2] 4a a7 [2] 0d a5 [2] 4a b4 [2] 04 b8 [2] 08 b2 [2] 1f b9 [2] 04 f7 [2] 39 }

  condition:
    any of them
}