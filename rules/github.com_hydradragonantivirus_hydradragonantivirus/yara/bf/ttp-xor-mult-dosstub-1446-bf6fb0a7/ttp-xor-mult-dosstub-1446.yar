rule TTP_XOR_MULT_DOSStub_1446 {
  strings:
    $key_1446 = { 40 2e [2] 34 36 [2] 73 34 [2] 34 25 [2] 7a 29 [2] 76 23 [2] 61 28 [2] 7a 66 [2] 47 }

  condition:
    any of them
}