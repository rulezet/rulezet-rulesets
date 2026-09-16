rule TTP_XOR_MULT_DOSStub_7f45 {
  strings:
    $key_7f45 = { 2b 2d [2] 5f 35 [2] 18 37 [2] 5f 26 [2] 11 2a [2] 1d 20 [2] 0a 2b [2] 11 65 [2] 2c }

  condition:
    any of them
}