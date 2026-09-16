rule TTP_XOR_MULT_DOSStub_c3a3 {
  strings:
    $key_c3a3 = { 97 cb [2] e3 d3 [2] a4 d1 [2] e3 c0 [2] ad cc [2] a1 c6 [2] b6 cd [2] ad 83 [2] 90 }

  condition:
    any of them
}