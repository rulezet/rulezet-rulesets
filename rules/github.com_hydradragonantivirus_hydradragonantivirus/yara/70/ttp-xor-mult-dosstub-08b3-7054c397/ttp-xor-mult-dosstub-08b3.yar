rule TTP_XOR_MULT_DOSStub_08b3 {
  strings:
    $key_08b3 = { 5c db [2] 28 c3 [2] 6f c1 [2] 28 d0 [2] 66 dc [2] 6a d6 [2] 7d dd [2] 66 93 [2] 5b }

  condition:
    any of them
}