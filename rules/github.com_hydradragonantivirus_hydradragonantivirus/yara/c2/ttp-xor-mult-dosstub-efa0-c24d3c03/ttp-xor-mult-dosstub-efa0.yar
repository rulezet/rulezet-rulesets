rule TTP_XOR_MULT_DOSStub_efa0 {
  strings:
    $key_efa0 = { bb c8 [2] cf d0 [2] 88 d2 [2] cf c3 [2] 81 cf [2] 8d c5 [2] 9a ce [2] 81 80 [2] bc }

  condition:
    any of them
}