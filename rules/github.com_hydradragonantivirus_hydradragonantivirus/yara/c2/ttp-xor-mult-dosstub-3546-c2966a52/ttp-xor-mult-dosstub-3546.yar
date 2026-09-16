rule TTP_XOR_MULT_DOSStub_3546 {
  strings:
    $key_3546 = { 61 2e [2] 15 36 [2] 52 34 [2] 15 25 [2] 5b 29 [2] 57 23 [2] 40 28 [2] 5b 66 [2] 66 }

  condition:
    any of them
}