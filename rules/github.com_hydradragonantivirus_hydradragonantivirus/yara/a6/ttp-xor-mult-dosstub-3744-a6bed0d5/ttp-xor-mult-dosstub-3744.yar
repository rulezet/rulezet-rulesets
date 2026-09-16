rule TTP_XOR_MULT_DOSStub_3744 {
  strings:
    $key_3744 = { 63 2c [2] 17 34 [2] 50 36 [2] 17 27 [2] 59 2b [2] 55 21 [2] 42 2a [2] 59 64 [2] 64 }

  condition:
    any of them
}