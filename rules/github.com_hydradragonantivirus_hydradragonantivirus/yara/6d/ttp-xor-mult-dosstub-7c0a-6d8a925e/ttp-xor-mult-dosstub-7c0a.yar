rule TTP_XOR_MULT_DOSStub_7c0a {
  strings:
    $key_7c0a = { 28 62 [2] 5c 7a [2] 1b 78 [2] 5c 69 [2] 12 65 [2] 1e 6f [2] 09 64 [2] 12 2a [2] 2f }

  condition:
    any of them
}