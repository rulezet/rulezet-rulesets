rule TTP_XOR_MULT_DOSStub_0aa4 {
  strings:
    $key_0aa4 = { 5e cc [2] 2a d4 [2] 6d d6 [2] 2a c7 [2] 64 cb [2] 68 c1 [2] 7f ca [2] 64 84 [2] 59 }

  condition:
    any of them
}