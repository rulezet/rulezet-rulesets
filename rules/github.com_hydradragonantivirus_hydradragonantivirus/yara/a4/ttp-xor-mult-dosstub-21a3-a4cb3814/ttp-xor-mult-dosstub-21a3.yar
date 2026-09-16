rule TTP_XOR_MULT_DOSStub_21a3 {
  strings:
    $key_21a3 = { 75 cb [2] 01 d3 [2] 46 d1 [2] 01 c0 [2] 4f cc [2] 43 c6 [2] 54 cd [2] 4f 83 [2] 72 }

  condition:
    any of them
}