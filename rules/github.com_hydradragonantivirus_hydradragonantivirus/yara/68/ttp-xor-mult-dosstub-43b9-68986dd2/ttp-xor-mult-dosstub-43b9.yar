rule TTP_XOR_MULT_DOSStub_43b9 {
  strings:
    $key_43b9 = { 17 d1 [2] 63 c9 [2] 24 cb [2] 63 da [2] 2d d6 [2] 21 dc [2] 36 d7 [2] 2d 99 [2] 10 }

  condition:
    any of them
}