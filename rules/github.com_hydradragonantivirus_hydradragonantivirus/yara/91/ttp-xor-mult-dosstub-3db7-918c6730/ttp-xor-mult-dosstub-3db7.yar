rule TTP_XOR_MULT_DOSStub_3db7 {
  strings:
    $key_3db7 = { 69 df [2] 1d c7 [2] 5a c5 [2] 1d d4 [2] 53 d8 [2] 5f d2 [2] 48 d9 [2] 53 97 [2] 6e }

  condition:
    any of them
}