rule TTP_XOR_MULT_DOSStub_daa0 {
  strings:
    $key_daa0 = { 8e c8 [2] fa d0 [2] bd d2 [2] fa c3 [2] b4 cf [2] b8 c5 [2] af ce [2] b4 80 [2] 89 }

  condition:
    any of them
}