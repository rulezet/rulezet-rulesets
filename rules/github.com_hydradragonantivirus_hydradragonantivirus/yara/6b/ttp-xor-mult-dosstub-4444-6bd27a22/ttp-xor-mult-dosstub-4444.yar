rule TTP_XOR_MULT_DOSStub_4444 {
  strings:
    $key_4444 = { 10 2c [2] 64 34 [2] 23 36 [2] 64 27 [2] 2a 2b [2] 26 21 [2] 31 2a [2] 2a 64 [2] 17 }

  condition:
    any of them
}