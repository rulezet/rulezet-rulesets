rule TTP_XOR_MULT_DOSStub_49f0 {
  strings:
    $key_49f0 = { 1d 98 [2] 69 80 [2] 2e 82 [2] 69 93 [2] 27 9f [2] 2b 95 [2] 3c 9e [2] 27 d0 [2] 1a }

  condition:
    any of them
}