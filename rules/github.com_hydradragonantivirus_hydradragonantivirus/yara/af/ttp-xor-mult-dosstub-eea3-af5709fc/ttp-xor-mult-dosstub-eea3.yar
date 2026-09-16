rule TTP_XOR_MULT_DOSStub_eea3 {
  strings:
    $key_eea3 = { ba cb [2] ce d3 [2] 89 d1 [2] ce c0 [2] 80 cc [2] 8c c6 [2] 9b cd [2] 80 83 [2] bd }

  condition:
    any of them
}