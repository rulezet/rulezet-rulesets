rule TTP_XOR_MULT_DOSStub_7f48 {
  strings:
    $key_7f48 = { 2b 20 [2] 5f 38 [2] 18 3a [2] 5f 2b [2] 11 27 [2] 1d 2d [2] 0a 26 [2] 11 68 [2] 2c }

  condition:
    any of them
}