rule TTP_XOR_MULT_DOSStub_47a3 {
  strings:
    $key_47a3 = { 13 cb [2] 67 d3 [2] 20 d1 [2] 67 c0 [2] 29 cc [2] 25 c6 [2] 32 cd [2] 29 83 [2] 14 }

  condition:
    any of them
}