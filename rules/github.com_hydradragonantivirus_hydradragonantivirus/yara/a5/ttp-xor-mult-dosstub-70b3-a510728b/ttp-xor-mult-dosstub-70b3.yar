rule TTP_XOR_MULT_DOSStub_70b3 {
  strings:
    $key_70b3 = { 24 db [2] 50 c3 [2] 17 c1 [2] 50 d0 [2] 1e dc [2] 12 d6 [2] 05 dd [2] 1e 93 [2] 23 }

  condition:
    any of them
}