rule TTP_XOR_MULT_DOSStub_fea3 {
  strings:
    $key_fea3 = { aa cb [2] de d3 [2] 99 d1 [2] de c0 [2] 90 cc [2] 9c c6 [2] 8b cd [2] 90 83 [2] ad }

  condition:
    any of them
}