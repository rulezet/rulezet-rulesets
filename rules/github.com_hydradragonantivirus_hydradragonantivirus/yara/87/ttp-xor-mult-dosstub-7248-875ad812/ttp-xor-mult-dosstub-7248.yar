rule TTP_XOR_MULT_DOSStub_7248 {
  strings:
    $key_7248 = { 26 20 [2] 52 38 [2] 15 3a [2] 52 2b [2] 1c 27 [2] 10 2d [2] 07 26 [2] 1c 68 [2] 21 }

  condition:
    any of them
}