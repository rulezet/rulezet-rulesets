rule TTP_XOR_MULT_DOSStub_5c7a {
  strings:
    $key_5c7a = { 08 12 [2] 7c 0a [2] 3b 08 [2] 7c 19 [2] 32 15 [2] 3e 1f [2] 29 14 [2] 32 5a [2] 0f }

  condition:
    any of them
}