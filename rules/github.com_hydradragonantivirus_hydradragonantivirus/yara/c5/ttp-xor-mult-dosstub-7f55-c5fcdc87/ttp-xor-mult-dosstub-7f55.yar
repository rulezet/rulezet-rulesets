rule TTP_XOR_MULT_DOSStub_7f55 {
  strings:
    $key_7f55 = { 2b 3d [2] 5f 25 [2] 18 27 [2] 5f 36 [2] 11 3a [2] 1d 30 [2] 0a 3b [2] 11 75 [2] 2c }

  condition:
    any of them
}