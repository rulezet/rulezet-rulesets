rule TTP_XOR_MULT_DOSStub_491a {
  strings:
    $key_491a = { 1d 72 [2] 69 6a [2] 2e 68 [2] 69 79 [2] 27 75 [2] 2b 7f [2] 3c 74 [2] 27 3a [2] 1a }

  condition:
    any of them
}