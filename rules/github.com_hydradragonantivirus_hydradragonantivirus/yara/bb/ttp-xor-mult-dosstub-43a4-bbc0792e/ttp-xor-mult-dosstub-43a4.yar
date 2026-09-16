rule TTP_XOR_MULT_DOSStub_43a4 {
  strings:
    $key_43a4 = { 17 cc [2] 63 d4 [2] 24 d6 [2] 63 c7 [2] 2d cb [2] 21 c1 [2] 36 ca [2] 2d 84 [2] 10 }

  condition:
    any of them
}