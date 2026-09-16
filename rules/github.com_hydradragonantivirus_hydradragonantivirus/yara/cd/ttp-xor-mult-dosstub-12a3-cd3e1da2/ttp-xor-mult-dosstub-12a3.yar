rule TTP_XOR_MULT_DOSStub_12a3 {
  strings:
    $key_12a3 = { 46 cb [2] 32 d3 [2] 75 d1 [2] 32 c0 [2] 7c cc [2] 70 c6 [2] 67 cd [2] 7c 83 [2] 41 }

  condition:
    any of them
}