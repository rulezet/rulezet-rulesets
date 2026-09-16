rule TTP_XOR_MULT_DOSStub_43f4 {
  strings:
    $key_43f4 = { 17 9c [2] 63 84 [2] 24 86 [2] 63 97 [2] 2d 9b [2] 21 91 [2] 36 9a [2] 2d d4 [2] 10 }

  condition:
    any of them
}