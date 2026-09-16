rule TTP_XOR_MULT_DOSStub_c9b1 {
  strings:
    $key_c9b1 = { 9d d9 [2] e9 c1 [2] ae c3 [2] e9 d2 [2] a7 de [2] ab d4 [2] bc df [2] a7 91 [2] 9a }

  condition:
    any of them
}