rule TTP_XOR_MULT_DOSStub_1c7d {
  strings:
    $key_1c7d = { 48 15 [2] 3c 0d [2] 7b 0f [2] 3c 1e [2] 72 12 [2] 7e 18 [2] 69 13 [2] 72 5d [2] 4f }

  condition:
    any of them
}