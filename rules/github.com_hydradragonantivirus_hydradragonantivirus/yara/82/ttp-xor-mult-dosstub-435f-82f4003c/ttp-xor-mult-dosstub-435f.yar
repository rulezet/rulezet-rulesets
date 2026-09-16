rule TTP_XOR_MULT_DOSStub_435f {
  strings:
    $key_435f = { 17 37 [2] 63 2f [2] 24 2d [2] 63 3c [2] 2d 30 [2] 21 3a [2] 36 31 [2] 2d 7f [2] 10 }

  condition:
    any of them
}