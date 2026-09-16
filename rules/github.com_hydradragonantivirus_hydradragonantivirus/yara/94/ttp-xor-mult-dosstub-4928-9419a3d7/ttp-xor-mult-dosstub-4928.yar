rule TTP_XOR_MULT_DOSStub_4928 {
  strings:
    $key_4928 = { 1d 40 [2] 69 58 [2] 2e 5a [2] 69 4b [2] 27 47 [2] 2b 4d [2] 3c 46 [2] 27 08 [2] 1a }

  condition:
    any of them
}