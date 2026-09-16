rule TTP_XOR_MULT_DOSStub_1644 {
  strings:
    $key_1644 = { 42 2c [2] 36 34 [2] 71 36 [2] 36 27 [2] 78 2b [2] 74 21 [2] 63 2a [2] 78 64 [2] 45 }

  condition:
    any of them
}