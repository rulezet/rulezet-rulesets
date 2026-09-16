rule TTP_XOR_MULT_DOSStub_2170 {
  strings:
    $key_2170 = { 75 18 [2] 01 00 [2] 46 02 [2] 01 13 [2] 4f 1f [2] 43 15 [2] 54 1e [2] 4f 50 [2] 72 }

  condition:
    any of them
}