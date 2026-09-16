rule TTP_XOR_MULT_DOSStub_5a70 {
  strings:
    $key_5a70 = { 0e 18 [2] 7a 00 [2] 3d 02 [2] 7a 13 [2] 34 1f [2] 38 15 [2] 2f 1e [2] 34 50 [2] 09 }

  condition:
    any of them
}