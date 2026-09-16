rule TTP_XOR_MULT_DOSStub_56a3 {
  strings:
    $key_56a3 = { 02 cb [2] 76 d3 [2] 31 d1 [2] 76 c0 [2] 38 cc [2] 34 c6 [2] 23 cd [2] 38 83 [2] 05 }

  condition:
    any of them
}