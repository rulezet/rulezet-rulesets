rule TTP_XOR_MULT_DOSStub_2db7 {
  strings:
    $key_2db7 = { 79 df [2] 0d c7 [2] 4a c5 [2] 0d d4 [2] 43 d8 [2] 4f d2 [2] 58 d9 [2] 43 97 [2] 7e }

  condition:
    any of them
}