rule TTP_XOR_MULT_DOSStub_34a3 {
  strings:
    $key_34a3 = { 60 cb [2] 14 d3 [2] 53 d1 [2] 14 c0 [2] 5a cc [2] 56 c6 [2] 41 cd [2] 5a 83 [2] 67 }

  condition:
    any of them
}