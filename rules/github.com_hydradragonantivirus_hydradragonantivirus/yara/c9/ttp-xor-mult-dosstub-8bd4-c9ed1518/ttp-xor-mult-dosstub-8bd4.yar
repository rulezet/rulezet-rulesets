rule TTP_XOR_MULT_DOSStub_8bd4 {
  strings:
    $key_8bd4 = { df bc [2] ab a4 [2] ec a6 [2] ab b7 [2] e5 bb [2] e9 b1 [2] fe ba [2] e5 f4 [2] d8 }

  condition:
    any of them
}