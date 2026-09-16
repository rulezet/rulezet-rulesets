rule TTP_XOR_MULT_DOSStub_4940 {
  strings:
    $key_4940 = { 1d 28 [2] 69 30 [2] 2e 32 [2] 69 23 [2] 27 2f [2] 2b 25 [2] 3c 2e [2] 27 60 [2] 1a }

  condition:
    any of them
}