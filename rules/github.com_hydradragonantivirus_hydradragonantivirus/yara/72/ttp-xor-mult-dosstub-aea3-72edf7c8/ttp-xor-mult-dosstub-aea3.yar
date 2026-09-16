rule TTP_XOR_MULT_DOSStub_aea3 {
  strings:
    $key_aea3 = { fa cb [2] 8e d3 [2] c9 d1 [2] 8e c0 [2] c0 cc [2] cc c6 [2] db cd [2] c0 83 [2] fd }

  condition:
    any of them
}