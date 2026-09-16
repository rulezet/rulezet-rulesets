rule TTP_XOR_MULT_DOSStub_2176 {
  strings:
    $key_2176 = { 75 1e [2] 01 06 [2] 46 04 [2] 01 15 [2] 4f 19 [2] 43 13 [2] 54 18 [2] 4f 56 [2] 72 }

  condition:
    any of them
}