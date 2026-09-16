rule TTP_XOR_MULT_DOSStub_4f48 {
  strings:
    $key_4f48 = { 1b 20 [2] 6f 38 [2] 28 3a [2] 6f 2b [2] 21 27 [2] 2d 2d [2] 3a 26 [2] 21 68 [2] 1c }

  condition:
    any of them
}