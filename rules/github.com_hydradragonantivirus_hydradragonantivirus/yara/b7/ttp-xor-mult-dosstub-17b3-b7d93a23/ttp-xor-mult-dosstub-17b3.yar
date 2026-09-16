rule TTP_XOR_MULT_DOSStub_17b3 {
  strings:
    $key_17b3 = { 43 db [2] 37 c3 [2] 70 c1 [2] 37 d0 [2] 79 dc [2] 75 d6 [2] 62 dd [2] 79 93 [2] 44 }

  condition:
    any of them
}