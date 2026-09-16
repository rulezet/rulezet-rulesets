rule TTP_XOR_MULT_DOSStub_41a3 {
  strings:
    $key_41a3 = { 15 cb [2] 61 d3 [2] 26 d1 [2] 61 c0 [2] 2f cc [2] 23 c6 [2] 34 cd [2] 2f 83 [2] 12 }

  condition:
    any of them
}