rule TTP_XOR_MULT_DOSStub_4574 {
  strings:
    $key_4574 = { 11 1c [2] 65 04 [2] 22 06 [2] 65 17 [2] 2b 1b [2] 27 11 [2] 30 1a [2] 2b 54 [2] 16 }

  condition:
    any of them
}