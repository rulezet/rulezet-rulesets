rule TTP_XOR_MULT_DOSStub_43f9 {
  strings:
    $key_43f9 = { 17 91 [2] 63 89 [2] 24 8b [2] 63 9a [2] 2d 96 [2] 21 9c [2] 36 97 [2] 2d d9 [2] 10 }

  condition:
    any of them
}