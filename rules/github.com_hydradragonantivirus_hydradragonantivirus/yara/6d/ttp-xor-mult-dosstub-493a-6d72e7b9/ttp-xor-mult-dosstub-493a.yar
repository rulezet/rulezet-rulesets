rule TTP_XOR_MULT_DOSStub_493a {
  strings:
    $key_493a = { 1d 52 [2] 69 4a [2] 2e 48 [2] 69 59 [2] 27 55 [2] 2b 5f [2] 3c 54 [2] 27 1a [2] 1a }

  condition:
    any of them
}