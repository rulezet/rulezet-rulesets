rule TTP_XOR_MULT_DOSStub_7f2d {
  strings:
    $key_7f2d = { 2b 45 [2] 5f 5d [2] 18 5f [2] 5f 4e [2] 11 42 [2] 1d 48 [2] 0a 43 [2] 11 0d [2] 2c }

  condition:
    any of them
}