rule TTP_XOR_MULT_DOSStub_1ad9 {
  strings:
    $key_1ad9 = { 4e b1 [2] 3a a9 [2] 7d ab [2] 3a ba [2] 74 b6 [2] 78 bc [2] 6f b7 [2] 74 f9 [2] 49 }

  condition:
    any of them
}