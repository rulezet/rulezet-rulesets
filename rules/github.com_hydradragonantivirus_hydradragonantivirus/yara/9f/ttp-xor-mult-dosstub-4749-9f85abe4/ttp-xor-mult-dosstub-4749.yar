rule TTP_XOR_MULT_DOSStub_4749 {
  strings:
    $key_4749 = { 13 21 [2] 67 39 [2] 20 3b [2] 67 2a [2] 29 26 [2] 25 2c [2] 32 27 [2] 29 69 [2] 14 }

  condition:
    any of them
}