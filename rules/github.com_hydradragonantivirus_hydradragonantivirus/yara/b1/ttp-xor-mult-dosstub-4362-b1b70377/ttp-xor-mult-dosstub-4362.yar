rule TTP_XOR_MULT_DOSStub_4362 {
  strings:
    $key_4362 = { 17 0a [2] 63 12 [2] 24 10 [2] 63 01 [2] 2d 0d [2] 21 07 [2] 36 0c [2] 2d 42 [2] 10 }

  condition:
    any of them
}