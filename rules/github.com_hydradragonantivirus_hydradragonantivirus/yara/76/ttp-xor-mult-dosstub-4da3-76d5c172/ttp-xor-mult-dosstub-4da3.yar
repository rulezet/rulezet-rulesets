rule TTP_XOR_MULT_DOSStub_4da3 {
  strings:
    $key_4da3 = { 19 cb [2] 6d d3 [2] 2a d1 [2] 6d c0 [2] 23 cc [2] 2f c6 [2] 38 cd [2] 23 83 [2] 1e }

  condition:
    any of them
}