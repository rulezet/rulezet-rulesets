rule TTP_XOR_MULT_DOSStub_4941 {
  strings:
    $key_4941 = { 1d 29 [2] 69 31 [2] 2e 33 [2] 69 22 [2] 27 2e [2] 2b 24 [2] 3c 2f [2] 27 61 [2] 1a }

  condition:
    any of them
}