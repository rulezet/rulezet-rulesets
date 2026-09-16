rule TTP_XOR_MULT_DOSStub_4479 {
  strings:
    $key_4479 = { 10 11 [2] 64 09 [2] 23 0b [2] 64 1a [2] 2a 16 [2] 26 1c [2] 31 17 [2] 2a 59 [2] 17 }

  condition:
    any of them
}