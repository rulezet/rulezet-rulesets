rule TTP_XOR_MULT_DOSStub_c9c7 {
  strings:
    $key_c9c7 = { 9d af [2] e9 b7 [2] ae b5 [2] e9 a4 [2] a7 a8 [2] ab a2 [2] bc a9 [2] a7 e7 [2] 9a }

  condition:
    any of them
}