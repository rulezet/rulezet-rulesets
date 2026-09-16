rule TTP_XOR_MULT_DOSStub_5046 {
  strings:
    $key_5046 = { 04 2e [2] 70 36 [2] 37 34 [2] 70 25 [2] 3e 29 [2] 32 23 [2] 25 28 [2] 3e 66 [2] 03 }

  condition:
    any of them
}