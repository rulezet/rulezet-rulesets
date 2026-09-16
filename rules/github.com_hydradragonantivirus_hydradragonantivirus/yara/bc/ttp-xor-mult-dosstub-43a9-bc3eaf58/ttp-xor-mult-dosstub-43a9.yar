rule TTP_XOR_MULT_DOSStub_43a9 {
  strings:
    $key_43a9 = { 17 c1 [2] 63 d9 [2] 24 db [2] 63 ca [2] 2d c6 [2] 21 cc [2] 36 c7 [2] 2d 89 [2] 10 }

  condition:
    any of them
}