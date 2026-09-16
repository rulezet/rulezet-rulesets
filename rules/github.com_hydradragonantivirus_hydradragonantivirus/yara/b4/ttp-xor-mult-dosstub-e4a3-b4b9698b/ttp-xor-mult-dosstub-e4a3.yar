rule TTP_XOR_MULT_DOSStub_e4a3 {
  strings:
    $key_e4a3 = { b0 cb [2] c4 d3 [2] 83 d1 [2] c4 c0 [2] 8a cc [2] 86 c6 [2] 91 cd [2] 8a 83 [2] b7 }

  condition:
    any of them
}