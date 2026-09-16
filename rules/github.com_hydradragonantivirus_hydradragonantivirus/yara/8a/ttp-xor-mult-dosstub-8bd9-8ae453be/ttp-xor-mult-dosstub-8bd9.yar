rule TTP_XOR_MULT_DOSStub_8bd9 {
  strings:
    $key_8bd9 = { df b1 [2] ab a9 [2] ec ab [2] ab ba [2] e5 b6 [2] e9 bc [2] fe b7 [2] e5 f9 [2] d8 }

  condition:
    any of them
}