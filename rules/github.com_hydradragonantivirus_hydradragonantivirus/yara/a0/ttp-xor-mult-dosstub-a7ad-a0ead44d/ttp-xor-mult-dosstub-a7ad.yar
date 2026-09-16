rule TTP_XOR_MULT_DOSStub_a7ad {
  strings:
    $key_a7ad = { f3 c5 [2] 87 dd [2] c0 df [2] 87 ce [2] c9 c2 [2] c5 c8 [2] d2 c3 [2] c9 8d [2] f4 }

  condition:
    any of them
}