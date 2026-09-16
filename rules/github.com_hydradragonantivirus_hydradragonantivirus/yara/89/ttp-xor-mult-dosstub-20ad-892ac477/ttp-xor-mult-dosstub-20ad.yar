rule TTP_XOR_MULT_DOSStub_20ad {
  strings:
    $key_20ad = { 74 c5 [2] 00 dd [2] 47 df [2] 00 ce [2] 4e c2 [2] 42 c8 [2] 55 c3 [2] 4e 8d [2] 73 }

  condition:
    any of them
}