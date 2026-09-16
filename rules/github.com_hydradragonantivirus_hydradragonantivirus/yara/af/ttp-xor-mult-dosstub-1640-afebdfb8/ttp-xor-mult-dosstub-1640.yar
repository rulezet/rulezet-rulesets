rule TTP_XOR_MULT_DOSStub_1640 {
  strings:
    $key_1640 = { 42 28 [2] 36 30 [2] 71 32 [2] 36 23 [2] 78 2f [2] 74 25 [2] 63 2e [2] 78 60 [2] 45 }

  condition:
    any of them
}