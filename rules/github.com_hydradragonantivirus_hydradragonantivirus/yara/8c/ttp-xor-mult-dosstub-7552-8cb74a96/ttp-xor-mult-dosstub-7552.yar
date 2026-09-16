rule TTP_XOR_MULT_DOSStub_7552 {
  strings:
    $key_7552 = { 21 3a [2] 55 22 [2] 12 20 [2] 55 31 [2] 1b 3d [2] 17 37 [2] 00 3c [2] 1b 72 [2] 26 }

  condition:
    any of them
}