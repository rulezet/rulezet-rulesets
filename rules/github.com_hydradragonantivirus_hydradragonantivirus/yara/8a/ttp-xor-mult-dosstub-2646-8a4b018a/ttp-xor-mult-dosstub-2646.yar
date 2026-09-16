rule TTP_XOR_MULT_DOSStub_2646 {
  strings:
    $key_2646 = { 72 2e [2] 06 36 [2] 41 34 [2] 06 25 [2] 48 29 [2] 44 23 [2] 53 28 [2] 48 66 [2] 75 }

  condition:
    any of them
}