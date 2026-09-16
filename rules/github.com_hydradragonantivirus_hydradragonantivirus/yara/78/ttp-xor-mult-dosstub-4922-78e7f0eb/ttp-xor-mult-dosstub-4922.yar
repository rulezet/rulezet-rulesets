rule TTP_XOR_MULT_DOSStub_4922 {
  strings:
    $key_4922 = { 1d 4a [2] 69 52 [2] 2e 50 [2] 69 41 [2] 27 4d [2] 2b 47 [2] 3c 4c [2] 27 02 [2] 1a }

  condition:
    any of them
}