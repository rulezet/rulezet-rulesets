rule TTP_XOR_MULT_DOSStub_21ad {
  strings:
    $key_21ad = { 75 c5 [2] 01 dd [2] 46 df [2] 01 ce [2] 4f c2 [2] 43 c8 [2] 54 c3 [2] 4f 8d [2] 72 }

  condition:
    any of them
}