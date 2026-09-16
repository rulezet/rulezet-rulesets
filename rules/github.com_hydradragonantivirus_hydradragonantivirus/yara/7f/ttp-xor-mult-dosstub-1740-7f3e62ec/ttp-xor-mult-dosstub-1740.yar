rule TTP_XOR_MULT_DOSStub_1740 {
  strings:
    $key_1740 = { 43 28 [2] 37 30 [2] 70 32 [2] 37 23 [2] 79 2f [2] 75 25 [2] 62 2e [2] 79 60 [2] 44 }

  condition:
    any of them
}