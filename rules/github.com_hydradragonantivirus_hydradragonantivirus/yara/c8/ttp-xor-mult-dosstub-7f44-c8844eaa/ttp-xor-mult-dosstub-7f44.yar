rule TTP_XOR_MULT_DOSStub_7f44 {
  strings:
    $key_7f44 = { 2b 2c [2] 5f 34 [2] 18 36 [2] 5f 27 [2] 11 2b [2] 1d 21 [2] 0a 2a [2] 11 64 [2] 2c }

  condition:
    any of them
}