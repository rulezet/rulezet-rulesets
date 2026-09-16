rule TTP_XOR_MULT_DOSStub_70a3 {
  strings:
    $key_70a3 = { 24 cb [2] 50 d3 [2] 17 d1 [2] 50 c0 [2] 1e cc [2] 12 c6 [2] 05 cd [2] 1e 83 [2] 23 }

  condition:
    any of them
}