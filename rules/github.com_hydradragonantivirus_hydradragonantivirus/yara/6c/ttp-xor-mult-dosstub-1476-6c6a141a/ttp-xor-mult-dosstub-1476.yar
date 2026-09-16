rule TTP_XOR_MULT_DOSStub_1476 {
  strings:
    $key_1476 = { 40 1e [2] 34 06 [2] 73 04 [2] 34 15 [2] 7a 19 [2] 76 13 [2] 61 18 [2] 7a 56 [2] 47 }

  condition:
    any of them
}