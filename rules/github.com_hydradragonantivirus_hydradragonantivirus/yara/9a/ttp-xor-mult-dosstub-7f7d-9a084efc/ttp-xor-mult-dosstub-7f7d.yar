rule TTP_XOR_MULT_DOSStub_7f7d {
  strings:
    $key_7f7d = { 2b 15 [2] 5f 0d [2] 18 0f [2] 5f 1e [2] 11 12 [2] 1d 18 [2] 0a 13 [2] 11 5d [2] 2c }

  condition:
    any of them
}