rule TTP_XOR_MULT_DOSStub_7444 {
  strings:
    $key_7444 = { 20 2c [2] 54 34 [2] 13 36 [2] 54 27 [2] 1a 2b [2] 16 21 [2] 01 2a [2] 1a 64 [2] 27 }

  condition:
    any of them
}