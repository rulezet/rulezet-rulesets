rule TTP_XOR_MULT_DOSStub_c9b3 {
  strings:
    $key_c9b3 = { 9d db [2] e9 c3 [2] ae c1 [2] e9 d0 [2] a7 dc [2] ab d6 [2] bc dd [2] a7 93 [2] 9a }

  condition:
    any of them
}