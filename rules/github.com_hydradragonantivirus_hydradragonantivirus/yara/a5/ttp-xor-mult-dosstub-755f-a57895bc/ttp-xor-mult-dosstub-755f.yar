rule TTP_XOR_MULT_DOSStub_755f {
  strings:
    $key_755f = { 21 37 [2] 55 2f [2] 12 2d [2] 55 3c [2] 1b 30 [2] 17 3a [2] 00 31 [2] 1b 7f [2] 26 }

  condition:
    any of them
}