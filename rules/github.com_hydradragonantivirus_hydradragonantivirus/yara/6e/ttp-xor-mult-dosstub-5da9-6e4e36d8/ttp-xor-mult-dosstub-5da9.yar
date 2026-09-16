rule TTP_XOR_MULT_DOSStub_5da9 {
  strings:
    $key_5da9 = { 09 c1 [2] 7d d9 [2] 3a db [2] 7d ca [2] 33 c6 [2] 3f cc [2] 28 c7 [2] 33 89 [2] 0e }

  condition:
    any of them
}