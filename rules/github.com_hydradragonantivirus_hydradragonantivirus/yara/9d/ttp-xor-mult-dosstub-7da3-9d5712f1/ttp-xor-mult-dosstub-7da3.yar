rule TTP_XOR_MULT_DOSStub_7da3 {
  strings:
    $key_7da3 = { 29 cb [2] 5d d3 [2] 1a d1 [2] 5d c0 [2] 13 cc [2] 1f c6 [2] 08 cd [2] 13 83 [2] 2e }

  condition:
    any of them
}