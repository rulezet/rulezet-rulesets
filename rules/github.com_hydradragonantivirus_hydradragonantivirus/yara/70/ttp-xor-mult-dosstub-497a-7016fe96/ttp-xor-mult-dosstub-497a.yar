rule TTP_XOR_MULT_DOSStub_497a {
  strings:
    $key_497a = { 1d 12 [2] 69 0a [2] 2e 08 [2] 69 19 [2] 27 15 [2] 2b 1f [2] 3c 14 [2] 27 5a [2] 1a }

  condition:
    any of them
}