rule TTP_XOR_MULT_DOSStub_3344 {
  strings:
    $key_3344 = { 67 2c [2] 13 34 [2] 54 36 [2] 13 27 [2] 5d 2b [2] 51 21 [2] 46 2a [2] 5d 64 [2] 60 }

  condition:
    any of them
}