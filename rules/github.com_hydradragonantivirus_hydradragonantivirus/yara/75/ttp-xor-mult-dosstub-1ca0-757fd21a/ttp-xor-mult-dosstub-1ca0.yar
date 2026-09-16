rule TTP_XOR_MULT_DOSStub_1ca0 {
  strings:
    $key_1ca0 = { 48 c8 [2] 3c d0 [2] 7b d2 [2] 3c c3 [2] 72 cf [2] 7e c5 [2] 69 ce [2] 72 80 [2] 4f }

  condition:
    any of them
}