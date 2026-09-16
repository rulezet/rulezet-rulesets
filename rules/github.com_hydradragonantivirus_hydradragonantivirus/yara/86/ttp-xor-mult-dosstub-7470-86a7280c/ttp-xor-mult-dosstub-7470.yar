rule TTP_XOR_MULT_DOSStub_7470 {
  strings:
    $key_7470 = { 20 18 [2] 54 00 [2] 13 02 [2] 54 13 [2] 1a 1f [2] 16 15 [2] 01 1e [2] 1a 50 [2] 27 }

  condition:
    any of them
}