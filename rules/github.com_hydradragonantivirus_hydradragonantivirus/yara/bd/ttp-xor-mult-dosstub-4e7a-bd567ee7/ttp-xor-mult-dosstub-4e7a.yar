rule TTP_XOR_MULT_DOSStub_4e7a {
  strings:
    $key_4e7a = { 1a 12 [2] 6e 0a [2] 29 08 [2] 6e 19 [2] 20 15 [2] 2c 1f [2] 3b 14 [2] 20 5a [2] 1d }

  condition:
    any of them
}