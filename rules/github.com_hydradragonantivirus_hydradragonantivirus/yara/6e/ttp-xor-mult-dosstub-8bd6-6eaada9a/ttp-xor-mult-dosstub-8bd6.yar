rule TTP_XOR_MULT_DOSStub_8bd6 {
  strings:
    $key_8bd6 = { df be [2] ab a6 [2] ec a4 [2] ab b5 [2] e5 b9 [2] e9 b3 [2] fe b8 [2] e5 f6 [2] d8 }

  condition:
    any of them
}