rule TTP_XOR_MULT_DOSStub_4959 {
  strings:
    $key_4959 = { 1d 31 [2] 69 29 [2] 2e 2b [2] 69 3a [2] 27 36 [2] 2b 3c [2] 3c 37 [2] 27 79 [2] 1a }

  condition:
    any of them
}