rule TTP_XOR_MULT_DOSStub_43a8 {
  strings:
    $key_43a8 = { 17 c0 [2] 63 d8 [2] 24 da [2] 63 cb [2] 2d c7 [2] 21 cd [2] 36 c6 [2] 2d 88 [2] 10 }

  condition:
    any of them
}