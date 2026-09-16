rule TTP_XOR_MULT_DOSStub_3e4a {
  strings:
    $key_3e4a = { 6a 22 [2] 1e 3a [2] 59 38 [2] 1e 29 [2] 50 25 [2] 5c 2f [2] 4b 24 [2] 50 6a [2] 6d }

  condition:
    any of them
}