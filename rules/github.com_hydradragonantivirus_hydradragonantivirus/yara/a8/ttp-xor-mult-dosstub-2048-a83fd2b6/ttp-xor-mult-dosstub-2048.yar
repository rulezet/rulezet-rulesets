rule TTP_XOR_MULT_DOSStub_2048 {
  strings:
    $key_2048 = { 74 20 [2] 00 38 [2] 47 3a [2] 00 2b [2] 4e 27 [2] 42 2d [2] 55 26 [2] 4e 68 [2] 73 }

  condition:
    any of them
}