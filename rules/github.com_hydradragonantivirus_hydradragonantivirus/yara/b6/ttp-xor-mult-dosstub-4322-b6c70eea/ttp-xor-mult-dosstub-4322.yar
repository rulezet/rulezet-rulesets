rule TTP_XOR_MULT_DOSStub_4322 {
  strings:
    $key_4322 = { 17 4a [2] 63 52 [2] 24 50 [2] 63 41 [2] 2d 4d [2] 21 47 [2] 36 4c [2] 2d 02 [2] 10 }

  condition:
    any of them
}