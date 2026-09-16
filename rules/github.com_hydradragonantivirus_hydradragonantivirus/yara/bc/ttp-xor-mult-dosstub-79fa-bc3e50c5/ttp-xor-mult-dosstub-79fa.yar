rule TTP_XOR_MULT_DOSStub_79fa {
  strings:
    $key_79fa = { 2d 92 [2] 59 8a [2] 1e 88 [2] 59 99 [2] 17 95 [2] 1b 9f [2] 0c 94 [2] 17 da [2] 2a }

  condition:
    any of them
}