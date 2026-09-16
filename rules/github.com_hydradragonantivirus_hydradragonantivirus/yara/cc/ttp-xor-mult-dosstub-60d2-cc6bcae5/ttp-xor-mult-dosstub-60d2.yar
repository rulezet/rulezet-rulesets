rule TTP_XOR_MULT_DOSStub_60d2 {
  strings:
    $key_60d2 = { 34 ba [2] 40 a2 [2] 07 a0 [2] 40 b1 [2] 0e bd [2] 02 b7 [2] 15 bc [2] 0e f2 [2] 33 }

  condition:
    any of them
}