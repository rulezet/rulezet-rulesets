rule TTP_XOR_MULT_DOSStub_43e5 {
  strings:
    $key_43e5 = { 17 8d [2] 63 95 [2] 24 97 [2] 63 86 [2] 2d 8a [2] 21 80 [2] 36 8b [2] 2d c5 [2] 10 }

  condition:
    any of them
}