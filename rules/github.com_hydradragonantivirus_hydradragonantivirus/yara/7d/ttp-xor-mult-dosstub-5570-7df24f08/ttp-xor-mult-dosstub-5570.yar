rule TTP_XOR_MULT_DOSStub_5570 {
  strings:
    $key_5570 = { 01 18 [2] 75 00 [2] 32 02 [2] 75 13 [2] 3b 1f [2] 37 15 [2] 20 1e [2] 3b 50 [2] 06 }

  condition:
    any of them
}