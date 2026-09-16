rule TTP_XOR_MULT_DOSStub_a6bc {
  strings:
    $key_a6bc = { f2 d4 [2] 86 cc [2] c1 ce [2] 86 df [2] c8 d3 [2] c4 d9 [2] d3 d2 [2] c8 9c [2] f5 }

  condition:
    any of them
}