rule TTP_XOR_MULT_DOSStub_8bd0 {
  strings:
    $key_8bd0 = { df b8 [2] ab a0 [2] ec a2 [2] ab b3 [2] e5 bf [2] e9 b5 [2] fe be [2] e5 f0 [2] d8 }

  condition:
    any of them
}