rule TTP_XOR_MULT_DOSStub_4c4a {
  strings:
    $key_4c4a = { 18 22 [2] 6c 3a [2] 2b 38 [2] 6c 29 [2] 22 25 [2] 2e 2f [2] 39 24 [2] 22 6a [2] 1f }

  condition:
    any of them
}