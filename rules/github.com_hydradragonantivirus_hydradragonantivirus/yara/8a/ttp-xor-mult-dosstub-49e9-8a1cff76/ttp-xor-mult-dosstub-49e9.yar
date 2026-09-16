rule TTP_XOR_MULT_DOSStub_49e9 {
  strings:
    $key_49e9 = { 1d 81 [2] 69 99 [2] 2e 9b [2] 69 8a [2] 27 86 [2] 2b 8c [2] 3c 87 [2] 27 c9 [2] 1a }

  condition:
    any of them
}