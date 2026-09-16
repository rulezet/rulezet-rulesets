rule TTP_XOR_MULT_DOSStub_4744 {
  strings:
    $key_4744 = { 13 2c [2] 67 34 [2] 20 36 [2] 67 27 [2] 29 2b [2] 25 21 [2] 32 2a [2] 29 64 [2] 14 }

  condition:
    any of them
}