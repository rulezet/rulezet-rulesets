rule TTP_XOR_MULT_DOSStub_4074 {
  strings:
    $key_4074 = { 14 1c [2] 60 04 [2] 27 06 [2] 60 17 [2] 2e 1b [2] 22 11 [2] 35 1a [2] 2e 54 [2] 13 }

  condition:
    any of them
}