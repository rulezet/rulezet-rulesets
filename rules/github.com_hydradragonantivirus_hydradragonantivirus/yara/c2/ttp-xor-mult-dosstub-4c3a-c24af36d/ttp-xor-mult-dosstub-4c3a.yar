rule TTP_XOR_MULT_DOSStub_4c3a {
  strings:
    $key_4c3a = { 18 52 [2] 6c 4a [2] 2b 48 [2] 6c 59 [2] 22 55 [2] 2e 5f [2] 39 54 [2] 22 1a [2] 1f }

  condition:
    any of them
}