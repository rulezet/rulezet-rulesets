rule TTP_XOR_MULT_DOSStub_4746 {
  strings:
    $key_4746 = { 13 2e [2] 67 36 [2] 20 34 [2] 67 25 [2] 29 29 [2] 25 23 [2] 32 28 [2] 29 66 [2] 14 }

  condition:
    any of them
}