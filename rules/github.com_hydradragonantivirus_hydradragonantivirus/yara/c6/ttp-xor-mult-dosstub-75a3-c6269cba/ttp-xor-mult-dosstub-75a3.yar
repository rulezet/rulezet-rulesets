rule TTP_XOR_MULT_DOSStub_75a3 {
  strings:
    $key_75a3 = { 21 cb [2] 55 d3 [2] 12 d1 [2] 55 c0 [2] 1b cc [2] 17 c6 [2] 00 cd [2] 1b 83 [2] 26 }

  condition:
    any of them
}