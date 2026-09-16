rule TTP_XOR_MULT_DOSStub_4936 {
  strings:
    $key_4936 = { 1d 5e [2] 69 46 [2] 2e 44 [2] 69 55 [2] 27 59 [2] 2b 53 [2] 3c 58 [2] 27 16 [2] 1a }

  condition:
    any of them
}