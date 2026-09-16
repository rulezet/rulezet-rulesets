rule TTP_XOR_MULT_DOSStub_49e7 {
  strings:
    $key_49e7 = { 1d 8f [2] 69 97 [2] 2e 95 [2] 69 84 [2] 27 88 [2] 2b 82 [2] 3c 89 [2] 27 c7 [2] 1a }

  condition:
    any of them
}