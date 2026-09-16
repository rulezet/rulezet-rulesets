rule TTP_XOR_MULT_DOSStub_1544 {
  strings:
    $key_1544 = { 41 2c [2] 35 34 [2] 72 36 [2] 35 27 [2] 7b 2b [2] 77 21 [2] 60 2a [2] 7b 64 [2] 46 }

  condition:
    any of them
}