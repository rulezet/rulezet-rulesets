rule TTP_XOR_MULT_DOSStub_4176 {
  strings:
    $key_4176 = { 15 1e [2] 61 06 [2] 26 04 [2] 61 15 [2] 2f 19 [2] 23 13 [2] 34 18 [2] 2f 56 [2] 12 }

  condition:
    any of them
}