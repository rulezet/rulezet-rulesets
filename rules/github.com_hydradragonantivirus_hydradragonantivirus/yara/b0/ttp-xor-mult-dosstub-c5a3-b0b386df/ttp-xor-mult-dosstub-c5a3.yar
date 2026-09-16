rule TTP_XOR_MULT_DOSStub_c5a3 {
  strings:
    $key_c5a3 = { 91 cb [2] e5 d3 [2] a2 d1 [2] e5 c0 [2] ab cc [2] a7 c6 [2] b0 cd [2] ab 83 [2] 96 }

  condition:
    any of them
}