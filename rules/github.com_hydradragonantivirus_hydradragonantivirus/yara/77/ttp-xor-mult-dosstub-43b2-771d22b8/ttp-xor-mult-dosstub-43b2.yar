rule TTP_XOR_MULT_DOSStub_43b2 {
  strings:
    $key_43b2 = { 17 da [2] 63 c2 [2] 24 c0 [2] 63 d1 [2] 2d dd [2] 21 d7 [2] 36 dc [2] 2d 92 [2] 10 }

  condition:
    any of them
}