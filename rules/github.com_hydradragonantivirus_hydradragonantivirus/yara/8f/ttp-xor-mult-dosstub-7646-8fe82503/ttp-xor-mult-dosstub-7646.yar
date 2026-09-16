rule TTP_XOR_MULT_DOSStub_7646 {
  strings:
    $key_7646 = { 22 2e [2] 56 36 [2] 11 34 [2] 56 25 [2] 18 29 [2] 14 23 [2] 03 28 [2] 18 66 [2] 25 }

  condition:
    any of them
}