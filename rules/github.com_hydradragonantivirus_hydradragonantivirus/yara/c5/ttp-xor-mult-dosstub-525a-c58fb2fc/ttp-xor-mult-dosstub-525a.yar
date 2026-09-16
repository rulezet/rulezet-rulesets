rule TTP_XOR_MULT_DOSStub_525a {
  strings:
    $key_525a = { 06 32 [2] 72 2a [2] 35 28 [2] 72 39 [2] 3c 35 [2] 30 3f [2] 27 34 [2] 3c 7a [2] 01 }

  condition:
    any of them
}