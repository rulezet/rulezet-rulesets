rule TTP_XOR_MULT_DOSStub_3940 {
  strings:
    $key_3940 = { 6d 28 [2] 19 30 [2] 5e 32 [2] 19 23 [2] 57 2f [2] 5b 25 [2] 4c 2e [2] 57 60 [2] 6a }

  condition:
    any of them
}