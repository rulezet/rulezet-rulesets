rule TTP_XOR_MULT_DOSStub_5646 {
  strings:
    $key_5646 = { 02 2e [2] 76 36 [2] 31 34 [2] 76 25 [2] 38 29 [2] 34 23 [2] 23 28 [2] 38 66 [2] 05 }

  condition:
    any of them
}