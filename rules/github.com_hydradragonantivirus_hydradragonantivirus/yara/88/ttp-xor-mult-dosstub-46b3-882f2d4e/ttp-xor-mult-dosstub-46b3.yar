rule TTP_XOR_MULT_DOSStub_46b3 {
  strings:
    $key_46b3 = { 12 db [2] 66 c3 [2] 21 c1 [2] 66 d0 [2] 28 dc [2] 24 d6 [2] 33 dd [2] 28 93 [2] 15 }

  condition:
    any of them
}