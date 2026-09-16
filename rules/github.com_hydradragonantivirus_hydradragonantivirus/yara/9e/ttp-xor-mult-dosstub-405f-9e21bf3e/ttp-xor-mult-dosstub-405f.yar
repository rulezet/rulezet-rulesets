rule TTP_XOR_MULT_DOSStub_405f {
  strings:
    $key_405f = { 14 37 [2] 60 2f [2] 27 2d [2] 60 3c [2] 2e 30 [2] 22 3a [2] 35 31 [2] 2e 7f [2] 13 }

  condition:
    any of them
}