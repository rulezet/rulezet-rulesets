rule TTP_XOR_MULT_DOSStub_0356 {
  strings:
    $key_0356 = { 57 3e [2] 23 26 [2] 64 24 [2] 23 35 [2] 6d 39 [2] 61 33 [2] 76 38 [2] 6d 76 [2] 50 }

  condition:
    any of them
}