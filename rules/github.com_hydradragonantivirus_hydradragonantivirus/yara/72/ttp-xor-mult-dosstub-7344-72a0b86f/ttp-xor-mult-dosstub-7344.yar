rule TTP_XOR_MULT_DOSStub_7344 {
  strings:
    $key_7344 = { 27 2c [2] 53 34 [2] 14 36 [2] 53 27 [2] 1d 2b [2] 11 21 [2] 06 2a [2] 1d 64 [2] 20 }

  condition:
    any of them
}