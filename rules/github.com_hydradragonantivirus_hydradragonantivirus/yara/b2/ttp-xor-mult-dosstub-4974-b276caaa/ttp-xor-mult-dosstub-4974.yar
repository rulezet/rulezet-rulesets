rule TTP_XOR_MULT_DOSStub_4974 {
  strings:
    $key_4974 = { 1d 1c [2] 69 04 [2] 2e 06 [2] 69 17 [2] 27 1b [2] 2b 11 [2] 3c 1a [2] 27 54 [2] 1a }

  condition:
    any of them
}