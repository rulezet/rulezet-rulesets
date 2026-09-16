rule TTP_XOR_MULT_DOSStub_7c4a {
  strings:
    $key_7c4a = { 28 22 [2] 5c 3a [2] 1b 38 [2] 5c 29 [2] 12 25 [2] 1e 2f [2] 09 24 [2] 12 6a [2] 2f }

  condition:
    any of them
}