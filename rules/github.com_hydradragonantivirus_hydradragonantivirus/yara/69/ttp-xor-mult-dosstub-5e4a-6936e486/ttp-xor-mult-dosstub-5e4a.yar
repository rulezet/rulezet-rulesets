rule TTP_XOR_MULT_DOSStub_5e4a {
  strings:
    $key_5e4a = { 0a 22 [2] 7e 3a [2] 39 38 [2] 7e 29 [2] 30 25 [2] 3c 2f [2] 2b 24 [2] 30 6a [2] 0d }

  condition:
    any of them
}