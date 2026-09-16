rule TTP_XOR_MULT_DOSStub_f1a3 {
  strings:
    $key_f1a3 = { a5 cb [2] d1 d3 [2] 96 d1 [2] d1 c0 [2] 9f cc [2] 93 c6 [2] 84 cd [2] 9f 83 [2] a2 }

  condition:
    any of them
}