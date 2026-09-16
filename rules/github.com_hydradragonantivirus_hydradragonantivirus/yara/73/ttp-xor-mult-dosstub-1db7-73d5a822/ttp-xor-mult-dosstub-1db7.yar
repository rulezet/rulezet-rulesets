rule TTP_XOR_MULT_DOSStub_1db7 {
  strings:
    $key_1db7 = { 49 df [2] 3d c7 [2] 7a c5 [2] 3d d4 [2] 73 d8 [2] 7f d2 [2] 68 d9 [2] 73 97 [2] 4e }

  condition:
    any of them
}