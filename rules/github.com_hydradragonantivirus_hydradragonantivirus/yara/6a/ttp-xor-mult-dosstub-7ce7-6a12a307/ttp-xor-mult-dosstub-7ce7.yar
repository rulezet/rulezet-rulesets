rule TTP_XOR_MULT_DOSStub_7ce7 {
  strings:
    $key_7ce7 = { 28 8f [2] 5c 97 [2] 1b 95 [2] 5c 84 [2] 12 88 [2] 1e 82 [2] 09 89 [2] 12 c7 [2] 2f }

  condition:
    any of them
}