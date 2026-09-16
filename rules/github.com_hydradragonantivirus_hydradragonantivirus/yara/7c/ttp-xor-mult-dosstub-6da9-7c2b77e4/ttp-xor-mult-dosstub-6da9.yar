rule TTP_XOR_MULT_DOSStub_6da9 {
  strings:
    $key_6da9 = { 39 c1 [2] 4d d9 [2] 0a db [2] 4d ca [2] 03 c6 [2] 0f cc [2] 18 c7 [2] 03 89 [2] 3e }

  condition:
    any of them
}