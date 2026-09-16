rule TTP_XOR_MULT_DOSStub_4960 {
  strings:
    $key_4960 = { 1d 08 [2] 69 10 [2] 2e 12 [2] 69 03 [2] 27 0f [2] 2b 05 [2] 3c 0e [2] 27 40 [2] 1a }

  condition:
    any of them
}