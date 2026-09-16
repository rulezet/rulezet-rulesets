rule TTP_XOR_MULT_DOSStub_43ee {
  strings:
    $key_43ee = { 17 86 [2] 63 9e [2] 24 9c [2] 63 8d [2] 2d 81 [2] 21 8b [2] 36 80 [2] 2d ce [2] 10 }

  condition:
    any of them
}