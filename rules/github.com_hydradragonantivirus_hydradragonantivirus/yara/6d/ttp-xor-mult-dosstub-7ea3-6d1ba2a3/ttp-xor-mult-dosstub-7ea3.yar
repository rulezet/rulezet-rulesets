rule TTP_XOR_MULT_DOSStub_7ea3 {
  strings:
    $key_7ea3 = { 2a cb [2] 5e d3 [2] 19 d1 [2] 5e c0 [2] 10 cc [2] 1c c6 [2] 0b cd [2] 10 83 [2] 2d }

  condition:
    any of them
}