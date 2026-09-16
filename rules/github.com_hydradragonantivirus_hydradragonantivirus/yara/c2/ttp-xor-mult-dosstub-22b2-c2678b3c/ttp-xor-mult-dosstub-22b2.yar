rule TTP_XOR_MULT_DOSStub_22b2 {
  strings:
    $key_22b2 = { 76 da [2] 02 c2 [2] 45 c0 [2] 02 d1 [2] 4c dd [2] 40 d7 [2] 57 dc [2] 4c 92 [2] 71 }

  condition:
    any of them
}