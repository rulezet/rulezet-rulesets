rule TTP_XOR_MULT_DOSStub_3da3 {
  strings:
    $key_3da3 = { 69 cb [2] 1d d3 [2] 5a d1 [2] 1d c0 [2] 53 cc [2] 5f c6 [2] 48 cd [2] 53 83 [2] 6e }

  condition:
    any of them
}