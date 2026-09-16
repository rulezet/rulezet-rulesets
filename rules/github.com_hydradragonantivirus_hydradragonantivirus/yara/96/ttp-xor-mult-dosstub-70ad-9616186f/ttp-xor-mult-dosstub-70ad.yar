rule TTP_XOR_MULT_DOSStub_70ad {
  strings:
    $key_70ad = { 24 c5 [2] 50 dd [2] 17 df [2] 50 ce [2] 1e c2 [2] 12 c8 [2] 05 c3 [2] 1e 8d [2] 23 }

  condition:
    any of them
}