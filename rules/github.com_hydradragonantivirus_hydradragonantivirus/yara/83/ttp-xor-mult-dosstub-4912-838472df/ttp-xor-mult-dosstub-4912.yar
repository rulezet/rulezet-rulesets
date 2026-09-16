rule TTP_XOR_MULT_DOSStub_4912 {
  strings:
    $key_4912 = { 1d 7a [2] 69 62 [2] 2e 60 [2] 69 71 [2] 27 7d [2] 2b 77 [2] 3c 7c [2] 27 32 [2] 1a }

  condition:
    any of them
}