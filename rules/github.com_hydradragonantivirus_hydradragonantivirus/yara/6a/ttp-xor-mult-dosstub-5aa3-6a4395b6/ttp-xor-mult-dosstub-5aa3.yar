rule TTP_XOR_MULT_DOSStub_5aa3 {
  strings:
    $key_5aa3 = { 0e cb [2] 7a d3 [2] 3d d1 [2] 7a c0 [2] 34 cc [2] 38 c6 [2] 2f cd [2] 34 83 [2] 09 }

  condition:
    any of them
}