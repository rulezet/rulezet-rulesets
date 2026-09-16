rule TTP_XOR_MULT_DOSStub_51a3 {
  strings:
    $key_51a3 = { 05 cb [2] 71 d3 [2] 36 d1 [2] 71 c0 [2] 3f cc [2] 33 c6 [2] 24 cd [2] 3f 83 [2] 02 }

  condition:
    any of them
}