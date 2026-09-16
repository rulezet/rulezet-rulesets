rule TTP_XOR_MULT_DOSStub_7a70 {
  strings:
    $key_7a70 = { 2e 18 [2] 5a 00 [2] 1d 02 [2] 5a 13 [2] 14 1f [2] 18 15 [2] 0f 1e [2] 14 50 [2] 29 }

  condition:
    any of them
}