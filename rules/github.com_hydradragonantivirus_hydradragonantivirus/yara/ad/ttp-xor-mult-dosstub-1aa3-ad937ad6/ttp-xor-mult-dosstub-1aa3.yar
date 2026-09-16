rule TTP_XOR_MULT_DOSStub_1aa3 {
  strings:
    $key_1aa3 = { 4e cb [2] 3a d3 [2] 7d d1 [2] 3a c0 [2] 74 cc [2] 78 c6 [2] 6f cd [2] 74 83 [2] 49 }

  condition:
    any of them
}