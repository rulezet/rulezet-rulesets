rule TTP_XOR_MULT_DOSStub_8bd3 {
  strings:
    $key_8bd3 = { df bb [2] ab a3 [2] ec a1 [2] ab b0 [2] e5 bc [2] e9 b6 [2] fe bd [2] e5 f3 [2] d8 }

  condition:
    any of them
}