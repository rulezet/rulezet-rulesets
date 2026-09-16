rule TTP_XOR_MULT_DOSStub_13a3 {
  strings:
    $key_13a3 = { 47 cb [2] 33 d3 [2] 74 d1 [2] 33 c0 [2] 7d cc [2] 71 c6 [2] 66 cd [2] 7d 83 [2] 40 }

  condition:
    any of them
}