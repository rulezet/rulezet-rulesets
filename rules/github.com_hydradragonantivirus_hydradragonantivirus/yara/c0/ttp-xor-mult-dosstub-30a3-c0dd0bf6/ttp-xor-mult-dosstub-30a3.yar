rule TTP_XOR_MULT_DOSStub_30a3 {
  strings:
    $key_30a3 = { 64 cb [2] 10 d3 [2] 57 d1 [2] 10 c0 [2] 5e cc [2] 52 c6 [2] 45 cd [2] 5e 83 [2] 63 }

  condition:
    any of them
}