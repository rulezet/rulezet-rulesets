rule TTP_XOR_MULT_DOSStub_5dbb {
  strings:
    $key_5dbb = { 09 d3 [2] 7d cb [2] 3a c9 [2] 7d d8 [2] 33 d4 [2] 3f de [2] 28 d5 [2] 33 9b [2] 0e }

  condition:
    any of them
}