rule TTP_XOR_MULT_DOSStub_4079 {
  strings:
    $key_4079 = { 14 11 [2] 60 09 [2] 27 0b [2] 60 1a [2] 2e 16 [2] 22 1c [2] 35 17 [2] 2e 59 [2] 13 }

  condition:
    any of them
}