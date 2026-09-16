rule TTP_XOR_MULT_DOSStub_4c2a {
  strings:
    $key_4c2a = { 18 42 [2] 6c 5a [2] 2b 58 [2] 6c 49 [2] 22 45 [2] 2e 4f [2] 39 44 [2] 22 0a [2] 1f }

  condition:
    any of them
}