rule TTP_XOR_MULT_DOSStub_7c7a {
  strings:
    $key_7c7a = { 28 12 [2] 5c 0a [2] 1b 08 [2] 5c 19 [2] 12 15 [2] 1e 1f [2] 09 14 [2] 12 5a [2] 2f }

  condition:
    any of them
}