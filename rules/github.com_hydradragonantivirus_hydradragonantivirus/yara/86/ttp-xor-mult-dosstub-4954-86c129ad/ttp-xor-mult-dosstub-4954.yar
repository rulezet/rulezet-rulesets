rule TTP_XOR_MULT_DOSStub_4954 {
  strings:
    $key_4954 = { 1d 3c [2] 69 24 [2] 2e 26 [2] 69 37 [2] 27 3b [2] 2b 31 [2] 3c 3a [2] 27 74 [2] 1a }

  condition:
    any of them
}