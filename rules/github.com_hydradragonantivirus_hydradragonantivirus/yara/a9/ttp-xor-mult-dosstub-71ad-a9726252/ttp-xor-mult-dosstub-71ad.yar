rule TTP_XOR_MULT_DOSStub_71ad {
  strings:
    $key_71ad = { 25 c5 [2] 51 dd [2] 16 df [2] 51 ce [2] 1f c2 [2] 13 c8 [2] 04 c3 [2] 1f 8d [2] 22 }

  condition:
    any of them
}