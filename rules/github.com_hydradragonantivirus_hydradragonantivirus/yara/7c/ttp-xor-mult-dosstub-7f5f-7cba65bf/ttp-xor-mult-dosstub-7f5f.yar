rule TTP_XOR_MULT_DOSStub_7f5f {
  strings:
    $key_7f5f = { 2b 37 [2] 5f 2f [2] 18 2d [2] 5f 3c [2] 11 30 [2] 1d 3a [2] 0a 31 [2] 11 7f [2] 2c }

  condition:
    any of them
}