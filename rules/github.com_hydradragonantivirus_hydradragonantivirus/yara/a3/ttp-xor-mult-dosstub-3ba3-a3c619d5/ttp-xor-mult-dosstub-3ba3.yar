rule TTP_XOR_MULT_DOSStub_3ba3 {
  strings:
    $key_3ba3 = { 6f cb [2] 1b d3 [2] 5c d1 [2] 1b c0 [2] 55 cc [2] 59 c6 [2] 4e cd [2] 55 83 [2] 68 }

  condition:
    any of them
}