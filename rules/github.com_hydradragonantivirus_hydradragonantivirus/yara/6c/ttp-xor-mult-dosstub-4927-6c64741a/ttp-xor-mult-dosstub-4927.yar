rule TTP_XOR_MULT_DOSStub_4927 {
  strings:
    $key_4927 = { 1d 4f [2] 69 57 [2] 2e 55 [2] 69 44 [2] 27 48 [2] 2b 42 [2] 3c 49 [2] 27 07 [2] 1a }

  condition:
    any of them
}