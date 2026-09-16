rule TTP_XOR_MULT_DOSStub_735f {
  strings:
    $key_735f = { 27 37 [2] 53 2f [2] 14 2d [2] 53 3c [2] 1d 30 [2] 11 3a [2] 06 31 [2] 1d 7f [2] 20 }

  condition:
    any of them
}