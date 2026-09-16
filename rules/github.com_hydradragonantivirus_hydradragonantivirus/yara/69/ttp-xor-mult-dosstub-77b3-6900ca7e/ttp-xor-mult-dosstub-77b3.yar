rule TTP_XOR_MULT_DOSStub_77b3 {
  strings:
    $key_77b3 = { 23 db [2] 57 c3 [2] 10 c1 [2] 57 d0 [2] 19 dc [2] 15 d6 [2] 02 dd [2] 19 93 [2] 24 }

  condition:
    any of them
}