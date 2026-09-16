rule TTP_XOR_MULT_DOSStub_a1ad {
  strings:
    $key_a1ad = { f5 c5 [2] 81 dd [2] c6 df [2] 81 ce [2] cf c2 [2] c3 c8 [2] d4 c3 [2] cf 8d [2] f2 }

  condition:
    any of them
}