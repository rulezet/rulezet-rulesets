rule TTP_XOR_MULT_DOSStub_40ad {
  strings:
    $key_40ad = { 14 c5 [2] 60 dd [2] 27 df [2] 60 ce [2] 2e c2 [2] 22 c8 [2] 35 c3 [2] 2e 8d [2] 13 }

  condition:
    any of them
}