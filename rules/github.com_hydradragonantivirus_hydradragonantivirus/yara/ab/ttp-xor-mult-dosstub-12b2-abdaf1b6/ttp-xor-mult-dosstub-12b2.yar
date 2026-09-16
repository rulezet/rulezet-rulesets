rule TTP_XOR_MULT_DOSStub_12b2 {
  strings:
    $key_12b2 = { 46 da [2] 32 c2 [2] 75 c0 [2] 32 d1 [2] 7c dd [2] 70 d7 [2] 67 dc [2] 7c 92 [2] 41 }

  condition:
    any of them
}