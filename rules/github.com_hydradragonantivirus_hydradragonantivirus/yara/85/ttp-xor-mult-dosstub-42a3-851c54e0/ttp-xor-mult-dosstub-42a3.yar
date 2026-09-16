rule TTP_XOR_MULT_DOSStub_42a3 {
  strings:
    $key_42a3 = { 16 cb [2] 62 d3 [2] 25 d1 [2] 62 c0 [2] 2c cc [2] 20 c6 [2] 37 cd [2] 2c 83 [2] 11 }

  condition:
    any of them
}