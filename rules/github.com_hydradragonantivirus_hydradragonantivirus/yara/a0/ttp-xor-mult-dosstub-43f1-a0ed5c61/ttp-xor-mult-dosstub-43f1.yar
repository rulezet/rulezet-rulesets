rule TTP_XOR_MULT_DOSStub_43f1 {
  strings:
    $key_43f1 = { 17 99 [2] 63 81 [2] 24 83 [2] 63 92 [2] 2d 9e [2] 21 94 [2] 36 9f [2] 2d d1 [2] 10 }

  condition:
    any of them
}