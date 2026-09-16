rule TTP_XOR_MULT_DOSStub_dba0 {
  strings:
    $key_dba0 = { 8f c8 [2] fb d0 [2] bc d2 [2] fb c3 [2] b5 cf [2] b9 c5 [2] ae ce [2] b5 80 [2] 88 }

  condition:
    any of them
}