rule TTP_XOR_MULT_DOSStub_32b2 {
  strings:
    $key_32b2 = { 66 da [2] 12 c2 [2] 55 c0 [2] 12 d1 [2] 5c dd [2] 50 d7 [2] 47 dc [2] 5c 92 [2] 61 }

  condition:
    any of them
}