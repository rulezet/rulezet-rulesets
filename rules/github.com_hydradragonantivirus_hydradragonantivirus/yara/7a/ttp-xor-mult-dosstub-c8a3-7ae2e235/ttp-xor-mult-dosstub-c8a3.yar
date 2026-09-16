rule TTP_XOR_MULT_DOSStub_c8a3 {
  strings:
    $key_c8a3 = { 9c cb [2] e8 d3 [2] af d1 [2] e8 c0 [2] a6 cc [2] aa c6 [2] bd cd [2] a6 83 [2] 9b }

  condition:
    any of them
}