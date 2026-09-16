rule TTP_XOR_MULT_DOSStub_6444 {
  strings:
    $key_6444 = { 30 2c [2] 44 34 [2] 03 36 [2] 44 27 [2] 0a 2b [2] 06 21 [2] 11 2a [2] 0a 64 [2] 37 }

  condition:
    any of them
}