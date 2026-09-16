rule TTP_XOR_MULT_DOSStub_6046 {
  strings:
    $key_6046 = { 34 2e [2] 40 36 [2] 07 34 [2] 40 25 [2] 0e 29 [2] 02 23 [2] 15 28 [2] 0e 66 [2] 33 }

  condition:
    any of them
}