rule TTP_XOR_MULT_DOSStub_64a3 {
  strings:
    $key_64a3 = { 30 cb [2] 44 d3 [2] 03 d1 [2] 44 c0 [2] 0a cc [2] 06 c6 [2] 11 cd [2] 0a 83 [2] 37 }

  condition:
    any of them
}