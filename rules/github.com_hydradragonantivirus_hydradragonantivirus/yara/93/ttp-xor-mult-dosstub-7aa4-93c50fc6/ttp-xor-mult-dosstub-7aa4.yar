rule TTP_XOR_MULT_DOSStub_7aa4 {
  strings:
    $key_7aa4 = { 2e cc [2] 5a d4 [2] 1d d6 [2] 5a c7 [2] 14 cb [2] 18 c1 [2] 0f ca [2] 14 84 [2] 29 }

  condition:
    any of them
}