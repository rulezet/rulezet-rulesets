rule TTP_XOR_MULT_DOSStub_35a3 {
  strings:
    $key_35a3 = { 61 cb [2] 15 d3 [2] 52 d1 [2] 15 c0 [2] 5b cc [2] 57 c6 [2] 40 cd [2] 5b 83 [2] 66 }

  condition:
    any of them
}