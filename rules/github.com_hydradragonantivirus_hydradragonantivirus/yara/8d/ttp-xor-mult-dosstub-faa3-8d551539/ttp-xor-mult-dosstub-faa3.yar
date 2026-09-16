rule TTP_XOR_MULT_DOSStub_faa3 {
  strings:
    $key_faa3 = { ae cb [2] da d3 [2] 9d d1 [2] da c0 [2] 94 cc [2] 98 c6 [2] 8f cd [2] 94 83 [2] a9 }

  condition:
    any of them
}