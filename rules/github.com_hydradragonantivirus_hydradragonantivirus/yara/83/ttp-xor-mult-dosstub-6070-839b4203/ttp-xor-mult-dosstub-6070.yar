rule TTP_XOR_MULT_DOSStub_6070 {
  strings:
    $key_6070 = { 34 18 [2] 40 00 [2] 07 02 [2] 40 13 [2] 0e 1f [2] 02 15 [2] 15 1e [2] 0e 50 [2] 33 }

  condition:
    any of them
}