rule TTP_XOR_MULT_DOSStub_0aa3 {
  strings:
    $key_0aa3 = { 5e cb [2] 2a d3 [2] 6d d1 [2] 2a c0 [2] 64 cc [2] 68 c6 [2] 7f cd [2] 64 83 [2] 59 }

  condition:
    any of them
}