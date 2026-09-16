rule TTP_XOR_MULT_DOSStub_4c5a {
  strings:
    $key_4c5a = { 18 32 [2] 6c 2a [2] 2b 28 [2] 6c 39 [2] 22 35 [2] 2e 3f [2] 39 34 [2] 22 7a [2] 1f }

  condition:
    any of them
}