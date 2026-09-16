rule TTP_XOR_MULT_DOSStub_4e5a {
  strings:
    $key_4e5a = { 1a 32 [2] 6e 2a [2] 29 28 [2] 6e 39 [2] 20 35 [2] 2c 3f [2] 3b 34 [2] 20 7a [2] 1d }

  condition:
    any of them
}