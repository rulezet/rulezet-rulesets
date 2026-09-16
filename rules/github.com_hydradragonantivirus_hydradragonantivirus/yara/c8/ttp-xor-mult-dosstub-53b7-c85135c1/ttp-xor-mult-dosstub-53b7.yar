rule TTP_XOR_MULT_DOSStub_53b7 {
  strings:
    $key_53b7 = { 07 df [2] 73 c7 [2] 34 c5 [2] 73 d4 [2] 3d d8 [2] 31 d2 [2] 26 d9 [2] 3d 97 [2] 00 }

  condition:
    any of them
}