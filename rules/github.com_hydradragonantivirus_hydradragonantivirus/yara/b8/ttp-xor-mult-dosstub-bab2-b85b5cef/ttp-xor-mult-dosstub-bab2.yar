rule TTP_XOR_MULT_DOSStub_bab2 {
  strings:
    $key_bab2 = { ee da [2] 9a c2 [2] dd c0 [2] 9a d1 [2] d4 dd [2] d8 d7 [2] cf dc [2] d4 92 [2] e9 }

  condition:
    any of them
}