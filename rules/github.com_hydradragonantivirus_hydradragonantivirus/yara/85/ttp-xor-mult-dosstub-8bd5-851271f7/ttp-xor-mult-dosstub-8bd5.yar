rule TTP_XOR_MULT_DOSStub_8bd5 {
  strings:
    $key_8bd5 = { df bd [2] ab a5 [2] ec a7 [2] ab b6 [2] e5 ba [2] e9 b0 [2] fe bb [2] e5 f5 [2] d8 }

  condition:
    any of them
}