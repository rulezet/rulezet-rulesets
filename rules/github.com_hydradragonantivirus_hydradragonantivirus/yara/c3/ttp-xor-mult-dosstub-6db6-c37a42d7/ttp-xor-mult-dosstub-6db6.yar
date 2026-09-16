rule TTP_XOR_MULT_DOSStub_6db6 {
  strings:
    $key_6db6 = { 39 de [2] 4d c6 [2] 0a c4 [2] 4d d5 [2] 03 d9 [2] 0f d3 [2] 18 d8 [2] 03 96 [2] 3e }

  condition:
    any of them
}