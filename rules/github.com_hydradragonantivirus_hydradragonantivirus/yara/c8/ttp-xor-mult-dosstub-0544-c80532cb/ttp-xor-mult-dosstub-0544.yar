rule TTP_XOR_MULT_DOSStub_0544 {
  strings:
    $key_0544 = { 51 2c [2] 25 34 [2] 62 36 [2] 25 27 [2] 6b 2b [2] 67 21 [2] 70 2a [2] 6b 64 [2] 56 }

  condition:
    any of them
}