rule TTP_XOR_MULT_DOSStub_52b2 {
  strings:
    $key_52b2 = { 06 da [2] 72 c2 [2] 35 c0 [2] 72 d1 [2] 3c dd [2] 30 d7 [2] 27 dc [2] 3c 92 [2] 01 }

  condition:
    any of them
}