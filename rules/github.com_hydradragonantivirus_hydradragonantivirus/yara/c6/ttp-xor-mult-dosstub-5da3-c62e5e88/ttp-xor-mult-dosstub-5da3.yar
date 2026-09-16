rule TTP_XOR_MULT_DOSStub_5da3 {
  strings:
    $key_5da3 = { 09 cb [2] 7d d3 [2] 3a d1 [2] 7d c0 [2] 33 cc [2] 3f c6 [2] 28 cd [2] 33 83 [2] 0e }

  condition:
    any of them
}