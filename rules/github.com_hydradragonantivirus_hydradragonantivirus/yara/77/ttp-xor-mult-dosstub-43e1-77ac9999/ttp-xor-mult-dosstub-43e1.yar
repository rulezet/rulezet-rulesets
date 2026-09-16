rule TTP_XOR_MULT_DOSStub_43e1 {
  strings:
    $key_43e1 = { 17 89 [2] 63 91 [2] 24 93 [2] 63 82 [2] 2d 8e [2] 21 84 [2] 36 8f [2] 2d c1 [2] 10 }

  condition:
    any of them
}