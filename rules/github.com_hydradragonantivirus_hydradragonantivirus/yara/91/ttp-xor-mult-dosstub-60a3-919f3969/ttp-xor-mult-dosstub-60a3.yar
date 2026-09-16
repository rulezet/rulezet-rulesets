rule TTP_XOR_MULT_DOSStub_60a3 {
  strings:
    $key_60a3 = { 34 cb [2] 40 d3 [2] 07 d1 [2] 40 c0 [2] 0e cc [2] 02 c6 [2] 15 cd [2] 0e 83 [2] 33 }

  condition:
    any of them
}