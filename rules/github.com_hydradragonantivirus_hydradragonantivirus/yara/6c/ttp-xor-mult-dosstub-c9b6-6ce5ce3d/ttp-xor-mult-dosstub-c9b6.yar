rule TTP_XOR_MULT_DOSStub_c9b6 {
  strings:
    $key_c9b6 = { 9d de [2] e9 c6 [2] ae c4 [2] e9 d5 [2] a7 d9 [2] ab d3 [2] bc d8 [2] a7 96 [2] 9a }

  condition:
    any of them
}