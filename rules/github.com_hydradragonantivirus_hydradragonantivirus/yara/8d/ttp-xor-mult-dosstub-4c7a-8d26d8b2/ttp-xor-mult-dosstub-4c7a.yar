rule TTP_XOR_MULT_DOSStub_4c7a {
  strings:
    $key_4c7a = { 18 12 [2] 6c 0a [2] 2b 08 [2] 6c 19 [2] 22 15 [2] 2e 1f [2] 39 14 [2] 22 5a [2] 1f }

  condition:
    any of them
}