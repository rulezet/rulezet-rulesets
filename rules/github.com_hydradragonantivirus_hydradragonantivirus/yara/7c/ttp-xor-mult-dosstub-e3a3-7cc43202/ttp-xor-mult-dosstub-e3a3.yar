rule TTP_XOR_MULT_DOSStub_e3a3 {
  strings:
    $key_e3a3 = { b7 cb [2] c3 d3 [2] 84 d1 [2] c3 c0 [2] 8d cc [2] 81 c6 [2] 96 cd [2] 8d 83 [2] b0 }

  condition:
    any of them
}