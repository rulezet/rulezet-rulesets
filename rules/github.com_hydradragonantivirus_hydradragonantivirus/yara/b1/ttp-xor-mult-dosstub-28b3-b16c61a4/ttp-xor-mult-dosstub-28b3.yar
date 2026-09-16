rule TTP_XOR_MULT_DOSStub_28b3 {
  strings:
    $key_28b3 = { 7c db [2] 08 c3 [2] 4f c1 [2] 08 d0 [2] 46 dc [2] 4a d6 [2] 5d dd [2] 46 93 [2] 7b }

  condition:
    any of them
}