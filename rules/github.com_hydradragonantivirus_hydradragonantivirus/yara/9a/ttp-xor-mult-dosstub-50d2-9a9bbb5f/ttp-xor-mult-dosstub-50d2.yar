rule TTP_XOR_MULT_DOSStub_50d2 {
  strings:
    $key_50d2 = { 04 ba [2] 70 a2 [2] 37 a0 [2] 70 b1 [2] 3e bd [2] 32 b7 [2] 25 bc [2] 3e f2 [2] 03 }

  condition:
    any of them
}