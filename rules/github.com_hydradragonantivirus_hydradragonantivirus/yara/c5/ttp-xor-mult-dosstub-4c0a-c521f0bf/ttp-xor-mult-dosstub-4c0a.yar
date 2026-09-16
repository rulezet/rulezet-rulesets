rule TTP_XOR_MULT_DOSStub_4c0a {
  strings:
    $key_4c0a = { 18 62 [2] 6c 7a [2] 2b 78 [2] 6c 69 [2] 22 65 [2] 2e 6f [2] 39 64 [2] 22 2a [2] 1f }

  condition:
    any of them
}