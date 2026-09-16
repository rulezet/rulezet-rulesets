rule TTP_XOR_MULT_DOSStub_435a {
  strings:
    $key_435a = { 17 32 [2] 63 2a [2] 24 28 [2] 63 39 [2] 2d 35 [2] 21 3f [2] 36 34 [2] 2d 7a [2] 10 }

  condition:
    any of them
}