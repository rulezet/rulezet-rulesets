rule TTP_XOR_MULT_DOSStub_7f2a {
  strings:
    $key_7f2a = { 2b 42 [2] 5f 5a [2] 18 58 [2] 5f 49 [2] 11 45 [2] 1d 4f [2] 0a 44 [2] 11 0a [2] 2c }

  condition:
    any of them
}