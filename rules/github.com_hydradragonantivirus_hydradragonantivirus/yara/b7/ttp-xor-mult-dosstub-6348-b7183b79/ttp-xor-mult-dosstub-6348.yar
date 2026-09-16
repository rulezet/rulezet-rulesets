rule TTP_XOR_MULT_DOSStub_6348 {
  strings:
    $key_6348 = { 37 20 [2] 43 38 [2] 04 3a [2] 43 2b [2] 0d 27 [2] 01 2d [2] 16 26 [2] 0d 68 [2] 30 }

  condition:
    any of them
}