rule TTP_XOR_MULT_DOSStub_43f5 {
  strings:
    $key_43f5 = { 17 9d [2] 63 85 [2] 24 87 [2] 63 96 [2] 2d 9a [2] 21 90 [2] 36 9b [2] 2d d5 [2] 10 }

  condition:
    any of them
}