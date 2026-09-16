rule TTP_XOR_MULT_DOSStub_4975 {
  strings:
    $key_4975 = { 1d 1d [2] 69 05 [2] 2e 07 [2] 69 16 [2] 27 1a [2] 2b 10 [2] 3c 1b [2] 27 55 [2] 1a }

  condition:
    any of them
}