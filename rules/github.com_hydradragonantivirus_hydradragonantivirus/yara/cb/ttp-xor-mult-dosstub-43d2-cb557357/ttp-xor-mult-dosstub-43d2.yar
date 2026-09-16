rule TTP_XOR_MULT_DOSStub_43d2 {
  strings:
    $key_43d2 = { 17 ba [2] 63 a2 [2] 24 a0 [2] 63 b1 [2] 2d bd [2] 21 b7 [2] 36 bc [2] 2d f2 [2] 10 }

  condition:
    any of them
}