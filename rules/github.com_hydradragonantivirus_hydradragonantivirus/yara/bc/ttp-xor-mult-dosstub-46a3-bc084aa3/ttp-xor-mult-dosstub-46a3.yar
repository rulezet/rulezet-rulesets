rule TTP_XOR_MULT_DOSStub_46a3 {
  strings:
    $key_46a3 = { 12 cb [2] 66 d3 [2] 21 d1 [2] 66 c0 [2] 28 cc [2] 24 c6 [2] 33 cd [2] 28 83 [2] 15 }

  condition:
    any of them
}