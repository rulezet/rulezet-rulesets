rule TTP_XOR_MULT_DOSStub_08b2 {
  strings:
    $key_08b2 = { 5c da [2] 28 c2 [2] 6f c0 [2] 28 d1 [2] 66 dd [2] 6a d7 [2] 7d dc [2] 66 92 [2] 5b }

  condition:
    any of them
}