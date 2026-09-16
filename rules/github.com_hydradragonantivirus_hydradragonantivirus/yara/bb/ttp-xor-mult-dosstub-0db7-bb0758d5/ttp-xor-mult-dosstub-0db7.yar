rule TTP_XOR_MULT_DOSStub_0db7 {
  strings:
    $key_0db7 = { 59 df [2] 2d c7 [2] 6a c5 [2] 2d d4 [2] 63 d8 [2] 6f d2 [2] 78 d9 [2] 63 97 [2] 5e }

  condition:
    any of them
}