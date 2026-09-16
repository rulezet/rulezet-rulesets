rule TTP_XOR_MULT_DOSStub_52a3 {
  strings:
    $key_52a3 = { 06 cb [2] 72 d3 [2] 35 d1 [2] 72 c0 [2] 3c cc [2] 30 c6 [2] 27 cd [2] 3c 83 [2] 01 }

  condition:
    any of them
}