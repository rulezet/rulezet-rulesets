rule TTP_XOR_MULT_DOSStub_a6ad {
  strings:
    $key_a6ad = { f2 c5 [2] 86 dd [2] c1 df [2] 86 ce [2] c8 c2 [2] c4 c8 [2] d3 c3 [2] c8 8d [2] f5 }

  condition:
    any of them
}