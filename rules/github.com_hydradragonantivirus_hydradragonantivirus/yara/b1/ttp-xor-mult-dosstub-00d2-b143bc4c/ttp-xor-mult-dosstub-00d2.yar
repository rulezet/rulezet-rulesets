rule TTP_XOR_MULT_DOSStub_00d2 {
  strings:
    $key_00d2 = { 54 ba [2] 20 a2 [2] 67 a0 [2] 20 b1 [2] 6e bd [2] 62 b7 [2] 75 bc [2] 6e f2 [2] 53 }

  condition:
    any of them
}