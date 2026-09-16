rule TTP_XOR_MULT_DOSStub_e7ad {
  strings:
    $key_e7ad = { b3 c5 [2] c7 dd [2] 80 df [2] c7 ce [2] 89 c2 [2] 85 c8 [2] 92 c3 [2] 89 8d [2] b4 }

  condition:
    any of them
}