rule TTP_XOR_MULT_DOSStub_8bc8 {
  strings:
    $key_8bc8 = { df a0 [2] ab b8 [2] ec ba [2] ab ab [2] e5 a7 [2] e9 ad [2] fe a6 [2] e5 e8 [2] d8 }

  condition:
    any of them
}