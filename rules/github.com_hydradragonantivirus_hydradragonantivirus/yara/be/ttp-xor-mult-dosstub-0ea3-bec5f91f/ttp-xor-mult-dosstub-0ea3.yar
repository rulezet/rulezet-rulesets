rule TTP_XOR_MULT_DOSStub_0ea3 {
  strings:
    $key_0ea3 = { 5a cb [2] 2e d3 [2] 69 d1 [2] 2e c0 [2] 60 cc [2] 6c c6 [2] 7b cd [2] 60 83 [2] 5d }

  condition:
    any of them
}