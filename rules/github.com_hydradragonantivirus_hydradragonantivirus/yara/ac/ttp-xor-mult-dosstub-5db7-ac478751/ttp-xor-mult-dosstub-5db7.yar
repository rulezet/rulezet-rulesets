rule TTP_XOR_MULT_DOSStub_5db7 {
  strings:
    $key_5db7 = { 09 df [2] 7d c7 [2] 3a c5 [2] 7d d4 [2] 33 d8 [2] 3f d2 [2] 28 d9 [2] 33 97 [2] 0e }

  condition:
    any of them
}