rule TTP_XOR_MULT_DOSStub_5231 {
  strings:
    $key_5231 = { 06 59 [2] 72 41 [2] 35 43 [2] 72 52 [2] 3c 5e [2] 30 54 [2] 27 5f [2] 3c 11 [2] 01 }

  condition:
    any of them
}