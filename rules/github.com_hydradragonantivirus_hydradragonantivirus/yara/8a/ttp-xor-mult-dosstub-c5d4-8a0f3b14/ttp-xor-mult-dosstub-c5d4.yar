rule TTP_XOR_MULT_DOSStub_c5d4 {
  strings:
    $key_c5d4 = { 91 bc [2] e5 a4 [2] a2 a6 [2] e5 b7 [2] ab bb [2] a7 b1 [2] b0 ba [2] ab f4 [2] 96 }

  condition:
    any of them
}