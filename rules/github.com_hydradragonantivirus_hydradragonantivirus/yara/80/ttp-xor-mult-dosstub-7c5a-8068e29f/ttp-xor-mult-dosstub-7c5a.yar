rule TTP_XOR_MULT_DOSStub_7c5a {
  strings:
    $key_7c5a = { 28 32 [2] 5c 2a [2] 1b 28 [2] 5c 39 [2] 12 35 [2] 1e 3f [2] 09 34 [2] 12 7a [2] 2f }

  condition:
    any of them
}