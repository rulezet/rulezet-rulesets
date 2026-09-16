rule TTP_XOR_MULT_DOSStub_7146 {
  strings:
    $key_7146 = { 25 2e [2] 51 36 [2] 16 34 [2] 51 25 [2] 1f 29 [2] 13 23 [2] 04 28 [2] 1f 66 [2] 22 }

  condition:
    any of them
}