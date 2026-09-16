rule TTP_XOR_MULT_DOSStub_7f43 {
  strings:
    $key_7f43 = { 2b 2b [2] 5f 33 [2] 18 31 [2] 5f 20 [2] 11 2c [2] 1d 26 [2] 0a 2d [2] 11 63 [2] 2c }

  condition:
    any of them
}