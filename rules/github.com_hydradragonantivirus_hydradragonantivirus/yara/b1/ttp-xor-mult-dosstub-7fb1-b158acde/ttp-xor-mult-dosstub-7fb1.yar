rule TTP_XOR_MULT_DOSStub_7fb1 {
  strings:
    $key_7fb1 = { 2b d9 [2] 5f c1 [2] 18 c3 [2] 5f d2 [2] 11 de [2] 1d d4 [2] 0a df [2] 11 91 [2] 2c }

  condition:
    any of them
}