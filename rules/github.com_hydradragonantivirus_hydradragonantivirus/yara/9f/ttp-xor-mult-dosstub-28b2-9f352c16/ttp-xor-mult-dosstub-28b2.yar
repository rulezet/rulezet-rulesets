rule TTP_XOR_MULT_DOSStub_28b2 {
  strings:
    $key_28b2 = { 7c da [2] 08 c2 [2] 4f c0 [2] 08 d1 [2] 46 dd [2] 4a d7 [2] 5d dc [2] 46 92 [2] 7b }

  condition:
    any of them
}