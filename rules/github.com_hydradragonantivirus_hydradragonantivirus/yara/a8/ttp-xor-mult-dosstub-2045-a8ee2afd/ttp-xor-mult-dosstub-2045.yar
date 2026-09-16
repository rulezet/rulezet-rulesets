rule TTP_XOR_MULT_DOSStub_2045 {
  strings:
    $key_2045 = { 74 2d [2] 00 35 [2] 47 37 [2] 00 26 [2] 4e 2a [2] 42 20 [2] 55 2b [2] 4e 65 [2] 73 }

  condition:
    any of them
}