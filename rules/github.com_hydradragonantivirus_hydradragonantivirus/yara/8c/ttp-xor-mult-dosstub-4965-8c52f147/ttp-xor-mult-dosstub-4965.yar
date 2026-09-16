rule TTP_XOR_MULT_DOSStub_4965 {
  strings:
    $key_4965 = { 1d 0d [2] 69 15 [2] 2e 17 [2] 69 06 [2] 27 0a [2] 2b 00 [2] 3c 0b [2] 27 45 [2] 1a }

  condition:
    any of them
}