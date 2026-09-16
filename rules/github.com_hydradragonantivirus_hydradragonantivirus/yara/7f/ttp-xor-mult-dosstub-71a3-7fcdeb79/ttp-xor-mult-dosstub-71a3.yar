rule TTP_XOR_MULT_DOSStub_71a3 {
  strings:
    $key_71a3 = { 25 cb [2] 51 d3 [2] 16 d1 [2] 51 c0 [2] 1f cc [2] 13 c6 [2] 04 cd [2] 1f 83 [2] 22 }

  condition:
    any of them
}