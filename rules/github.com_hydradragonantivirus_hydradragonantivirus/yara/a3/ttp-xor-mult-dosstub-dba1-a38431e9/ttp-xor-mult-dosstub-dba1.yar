rule TTP_XOR_MULT_DOSStub_dba1 {
  strings:
    $key_dba1 = { 8f c9 [2] fb d1 [2] bc d3 [2] fb c2 [2] b5 ce [2] b9 c4 [2] ae cf [2] b5 81 [2] 88 }

  condition:
    any of them
}