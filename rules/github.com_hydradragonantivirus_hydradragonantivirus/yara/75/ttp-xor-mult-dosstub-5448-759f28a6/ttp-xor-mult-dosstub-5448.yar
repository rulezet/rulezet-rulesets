rule TTP_XOR_MULT_DOSStub_5448 {
  strings:
    $key_5448 = { 00 20 [2] 74 38 [2] 33 3a [2] 74 2b [2] 3a 27 [2] 36 2d [2] 21 26 [2] 3a 68 [2] 07 }

  condition:
    any of them
}