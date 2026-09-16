rule TTP_XOR_MULT_DOSStub_3348 {
  strings:
    $key_3348 = { 67 20 [2] 13 38 [2] 54 3a [2] 13 2b [2] 5d 27 [2] 51 2d [2] 46 26 [2] 5d 68 [2] 60 }

  condition:
    any of them
}