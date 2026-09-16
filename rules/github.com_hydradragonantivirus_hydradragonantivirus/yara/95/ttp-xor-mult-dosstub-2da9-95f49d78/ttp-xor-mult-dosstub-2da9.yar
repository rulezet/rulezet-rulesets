rule TTP_XOR_MULT_DOSStub_2da9 {
  strings:
    $key_2da9 = { 79 c1 [2] 0d d9 [2] 4a db [2] 0d ca [2] 43 c6 [2] 4f cc [2] 58 c7 [2] 43 89 [2] 7e }

  condition:
    any of them
}