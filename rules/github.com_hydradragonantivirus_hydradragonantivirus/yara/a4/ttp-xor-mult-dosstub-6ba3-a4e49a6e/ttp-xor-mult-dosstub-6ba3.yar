rule TTP_XOR_MULT_DOSStub_6ba3 {
  strings:
    $key_6ba3 = { 3f cb [2] 4b d3 [2] 0c d1 [2] 4b c0 [2] 05 cc [2] 09 c6 [2] 1e cd [2] 05 83 [2] 38 }

  condition:
    any of them
}