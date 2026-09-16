rule TTP_XOR_MULT_DOSStub_5aa4 {
  strings:
    $key_5aa4 = { 0e cc [2] 7a d4 [2] 3d d6 [2] 7a c7 [2] 34 cb [2] 38 c1 [2] 2f ca [2] 34 84 [2] 09 }

  condition:
    any of them
}