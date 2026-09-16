rule TTP_XOR_MULT_DOSStub_3746 {
  strings:
    $key_3746 = { 63 2e [2] 17 36 [2] 50 34 [2] 17 25 [2] 59 29 [2] 55 23 [2] 42 28 [2] 59 66 [2] 64 }

  condition:
    any of them
}