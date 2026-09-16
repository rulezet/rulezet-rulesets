rule TTP_XOR_MULT_DOSStub_436f {
  strings:
    $key_436f = { 17 07 [2] 63 1f [2] 24 1d [2] 63 0c [2] 2d 00 [2] 21 0a [2] 36 01 [2] 2d 4f [2] 10 }

  condition:
    any of them
}