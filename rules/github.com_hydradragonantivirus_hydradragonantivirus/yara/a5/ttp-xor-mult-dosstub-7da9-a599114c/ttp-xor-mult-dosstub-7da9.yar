rule TTP_XOR_MULT_DOSStub_7da9 {
  strings:
    $key_7da9 = { 29 c1 [2] 5d d9 [2] 1a db [2] 5d ca [2] 13 c6 [2] 1f cc [2] 08 c7 [2] 13 89 [2] 2e }

  condition:
    any of them
}