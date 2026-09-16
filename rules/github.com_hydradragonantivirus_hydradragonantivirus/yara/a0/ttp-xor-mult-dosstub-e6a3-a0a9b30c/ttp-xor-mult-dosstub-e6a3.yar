rule TTP_XOR_MULT_DOSStub_e6a3 {
  strings:
    $key_e6a3 = { b2 cb [2] c6 d3 [2] 81 d1 [2] c6 c0 [2] 88 cc [2] 84 c6 [2] 93 cd [2] 88 83 [2] b5 }

  condition:
    any of them
}