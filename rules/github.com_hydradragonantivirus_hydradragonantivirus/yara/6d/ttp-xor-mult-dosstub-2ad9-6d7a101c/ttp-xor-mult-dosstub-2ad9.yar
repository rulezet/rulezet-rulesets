rule TTP_XOR_MULT_DOSStub_2ad9 {
  strings:
    $key_2ad9 = { 7e b1 [2] 0a a9 [2] 4d ab [2] 0a ba [2] 44 b6 [2] 48 bc [2] 5f b7 [2] 44 f9 [2] 79 }

  condition:
    any of them
}