rule TTP_XOR_MULT_DOSStub_74ad {
  strings:
    $key_74ad = { 20 c5 [2] 54 dd [2] 13 df [2] 54 ce [2] 1a c2 [2] 16 c8 [2] 01 c3 [2] 1a 8d [2] 27 }

  condition:
    any of them
}