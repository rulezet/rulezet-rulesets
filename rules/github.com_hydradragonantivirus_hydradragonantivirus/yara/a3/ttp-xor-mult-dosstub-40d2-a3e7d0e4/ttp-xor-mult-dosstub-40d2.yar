rule TTP_XOR_MULT_DOSStub_40d2 {
  strings:
    $key_40d2 = { 14 ba [2] 60 a2 [2] 27 a0 [2] 60 b1 [2] 2e bd [2] 22 b7 [2] 35 bc [2] 2e f2 [2] 13 }

  condition:
    any of them
}