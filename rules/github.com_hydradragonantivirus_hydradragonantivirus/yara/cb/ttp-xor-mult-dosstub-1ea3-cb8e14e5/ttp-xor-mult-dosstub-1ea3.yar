rule TTP_XOR_MULT_DOSStub_1ea3 {
  strings:
    $key_1ea3 = { 4a cb [2] 3e d3 [2] 79 d1 [2] 3e c0 [2] 70 cc [2] 7c c6 [2] 6b cd [2] 70 83 [2] 4d }

  condition:
    any of them
}