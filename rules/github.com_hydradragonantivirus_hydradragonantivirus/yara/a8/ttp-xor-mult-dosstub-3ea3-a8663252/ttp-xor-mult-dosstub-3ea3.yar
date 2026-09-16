rule TTP_XOR_MULT_DOSStub_3ea3 {
  strings:
    $key_3ea3 = { 6a cb [2] 1e d3 [2] 59 d1 [2] 1e c0 [2] 50 cc [2] 5c c6 [2] 4b cd [2] 50 83 [2] 6d }

  condition:
    any of them
}