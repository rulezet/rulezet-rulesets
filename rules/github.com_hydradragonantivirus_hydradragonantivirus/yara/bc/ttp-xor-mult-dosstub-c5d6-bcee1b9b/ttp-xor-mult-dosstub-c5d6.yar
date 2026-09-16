rule TTP_XOR_MULT_DOSStub_c5d6 {
  strings:
    $key_c5d6 = { 91 be [2] e5 a6 [2] a2 a4 [2] e5 b5 [2] ab b9 [2] a7 b3 [2] b0 b8 [2] ab f6 [2] 96 }

  condition:
    any of them
}