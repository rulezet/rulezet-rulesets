rule TTP_XOR_MULT_DOSStub_04ad {
  strings:
    $key_04ad = { 50 c5 [2] 24 dd [2] 63 df [2] 24 ce [2] 6a c2 [2] 66 c8 [2] 71 c3 [2] 6a 8d [2] 57 }

  condition:
    any of them
}