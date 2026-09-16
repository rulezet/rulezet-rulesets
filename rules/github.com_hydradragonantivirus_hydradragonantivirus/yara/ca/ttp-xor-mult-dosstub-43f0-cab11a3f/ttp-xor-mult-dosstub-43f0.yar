rule TTP_XOR_MULT_DOSStub_43f0 {
  strings:
    $key_43f0 = { 17 98 [2] 63 80 [2] 24 82 [2] 63 93 [2] 2d 9f [2] 21 95 [2] 36 9e [2] 2d d0 [2] 10 }

  condition:
    any of them
}