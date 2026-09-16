rule TTP_XOR_MULT_DOSStub_10a3 {
  strings:
    $key_10a3 = { 44 cb [2] 30 d3 [2] 77 d1 [2] 30 c0 [2] 7e cc [2] 72 c6 [2] 65 cd [2] 7e 83 [2] 43 }

  condition:
    any of them
}