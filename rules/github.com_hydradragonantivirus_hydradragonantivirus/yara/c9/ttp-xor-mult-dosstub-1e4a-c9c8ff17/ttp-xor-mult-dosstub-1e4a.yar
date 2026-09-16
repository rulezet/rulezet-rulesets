rule TTP_XOR_MULT_DOSStub_1e4a {
  strings:
    $key_1e4a = { 4a 22 [2] 3e 3a [2] 79 38 [2] 3e 29 [2] 70 25 [2] 7c 2f [2] 6b 24 [2] 70 6a [2] 4d }

  condition:
    any of them
}