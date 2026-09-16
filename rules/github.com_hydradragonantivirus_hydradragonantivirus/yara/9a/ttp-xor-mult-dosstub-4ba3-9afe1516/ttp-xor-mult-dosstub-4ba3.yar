rule TTP_XOR_MULT_DOSStub_4ba3 {
  strings:
    $key_4ba3 = { 1f cb [2] 6b d3 [2] 2c d1 [2] 6b c0 [2] 25 cc [2] 29 c6 [2] 3e cd [2] 25 83 [2] 18 }

  condition:
    any of them
}