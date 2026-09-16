rule TTP_XOR_MULT_DOSStub_4e0a {
  strings:
    $key_4e0a = { 1a 62 [2] 6e 7a [2] 29 78 [2] 6e 69 [2] 20 65 [2] 2c 6f [2] 3b 64 [2] 20 2a [2] 1d }

  condition:
    any of them
}