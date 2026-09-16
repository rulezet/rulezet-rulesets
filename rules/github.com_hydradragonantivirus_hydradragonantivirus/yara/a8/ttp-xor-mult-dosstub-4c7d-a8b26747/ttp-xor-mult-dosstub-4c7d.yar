rule TTP_XOR_MULT_DOSStub_4c7d {
  strings:
    $key_4c7d = { 18 15 [2] 6c 0d [2] 2b 0f [2] 6c 1e [2] 22 12 [2] 2e 18 [2] 39 13 [2] 22 5d [2] 1f }

  condition:
    any of them
}