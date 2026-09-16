rule TTP_XOR_MULT_DOSStub_4170 {
  strings:
    $key_4170 = { 15 18 [2] 61 00 [2] 26 02 [2] 61 13 [2] 2f 1f [2] 23 15 [2] 34 1e [2] 2f 50 [2] 12 }

  condition:
    any of them
}