rule TTP_XOR_MULT_DOSStub_7ca3 {
  strings:
    $key_7ca3 = { 28 cb [2] 5c d3 [2] 1b d1 [2] 5c c0 [2] 12 cc [2] 1e c6 [2] 09 cd [2] 12 83 [2] 2f }

  condition:
    any of them
}