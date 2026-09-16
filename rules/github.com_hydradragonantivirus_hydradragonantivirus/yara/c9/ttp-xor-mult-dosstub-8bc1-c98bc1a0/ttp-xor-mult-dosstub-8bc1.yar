rule TTP_XOR_MULT_DOSStub_8bc1 {
  strings:
    $key_8bc1 = { df a9 [2] ab b1 [2] ec b3 [2] ab a2 [2] e5 ae [2] e9 a4 [2] fe af [2] e5 e1 [2] d8 }

  condition:
    any of them
}