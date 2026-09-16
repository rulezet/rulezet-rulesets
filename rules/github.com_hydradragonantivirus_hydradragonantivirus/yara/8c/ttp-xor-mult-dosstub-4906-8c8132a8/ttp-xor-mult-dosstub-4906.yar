rule TTP_XOR_MULT_DOSStub_4906 {
  strings:
    $key_4906 = { 1d 6e [2] 69 76 [2] 2e 74 [2] 69 65 [2] 27 69 [2] 2b 63 [2] 3c 68 [2] 27 26 [2] 1a }

  condition:
    any of them
}