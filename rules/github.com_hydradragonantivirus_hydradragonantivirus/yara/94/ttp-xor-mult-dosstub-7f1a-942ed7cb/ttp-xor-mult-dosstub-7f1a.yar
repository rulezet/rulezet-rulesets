rule TTP_XOR_MULT_DOSStub_7f1a {
  strings:
    $key_7f1a = { 2b 72 [2] 5f 6a [2] 18 68 [2] 5f 79 [2] 11 75 [2] 1d 7f [2] 0a 74 [2] 11 3a [2] 2c }

  condition:
    any of them
}