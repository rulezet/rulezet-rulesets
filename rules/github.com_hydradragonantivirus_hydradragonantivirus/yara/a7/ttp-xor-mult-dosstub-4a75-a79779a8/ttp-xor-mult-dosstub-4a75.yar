rule TTP_XOR_MULT_DOSStub_4a75 {
  strings:
    $key_4a75 = { 1e 1d [2] 6a 05 [2] 2d 07 [2] 6a 16 [2] 24 1a [2] 28 10 [2] 3f 1b [2] 24 55 [2] 19 }

  condition:
    any of them
}