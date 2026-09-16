rule TTP_XOR_MULT_DOSStub_4938 {
  strings:
    $key_4938 = { 1d 50 [2] 69 48 [2] 2e 4a [2] 69 5b [2] 27 57 [2] 2b 5d [2] 3c 56 [2] 27 18 [2] 1a }

  condition:
    any of them
}