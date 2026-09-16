rule TTP_XOR_MULT_DOSStub_e9a0 {
  strings:
    $key_e9a0 = { bd c8 [2] c9 d0 [2] 8e d2 [2] c9 c3 [2] 87 cf [2] 8b c5 [2] 9c ce [2] 87 80 [2] ba }

  condition:
    any of them
}