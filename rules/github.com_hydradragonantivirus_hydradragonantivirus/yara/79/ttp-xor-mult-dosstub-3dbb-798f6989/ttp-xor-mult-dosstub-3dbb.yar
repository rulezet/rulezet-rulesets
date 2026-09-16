rule TTP_XOR_MULT_DOSStub_3dbb {
  strings:
    $key_3dbb = { 69 d3 [2] 1d cb [2] 5a c9 [2] 1d d8 [2] 53 d4 [2] 5f de [2] 48 d5 [2] 53 9b [2] 6e }

  condition:
    any of them
}