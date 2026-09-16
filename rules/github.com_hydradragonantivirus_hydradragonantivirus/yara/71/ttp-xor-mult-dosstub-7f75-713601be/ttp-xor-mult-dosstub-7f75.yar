rule TTP_XOR_MULT_DOSStub_7f75 {
  strings:
    $key_7f75 = { 2b 1d [2] 5f 05 [2] 18 07 [2] 5f 16 [2] 11 1a [2] 1d 10 [2] 0a 1b [2] 11 55 [2] 2c }

  condition:
    any of them
}