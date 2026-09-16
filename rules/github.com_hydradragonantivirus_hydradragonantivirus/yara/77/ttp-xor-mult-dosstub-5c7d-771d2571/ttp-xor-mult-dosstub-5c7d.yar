rule TTP_XOR_MULT_DOSStub_5c7d {
  strings:
    $key_5c7d = { 08 15 [2] 7c 0d [2] 3b 0f [2] 7c 1e [2] 32 12 [2] 3e 18 [2] 29 13 [2] 32 5d [2] 0f }

  condition:
    any of them
}