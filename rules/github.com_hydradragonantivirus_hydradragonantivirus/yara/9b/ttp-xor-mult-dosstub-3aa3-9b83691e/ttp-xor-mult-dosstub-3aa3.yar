rule TTP_XOR_MULT_DOSStub_3aa3 {
  strings:
    $key_3aa3 = { 6e cb [2] 1a d3 [2] 5d d1 [2] 1a c0 [2] 54 cc [2] 58 c6 [2] 4f cd [2] 54 83 [2] 69 }

  condition:
    any of them
}