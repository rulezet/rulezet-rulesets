rule TTP_XOR_MULT_DOSStub_c9c1 {
  strings:
    $key_c9c1 = { 9d a9 [2] e9 b1 [2] ae b3 [2] e9 a2 [2] a7 ae [2] ab a4 [2] bc af [2] a7 e1 [2] 9a }

  condition:
    any of them
}