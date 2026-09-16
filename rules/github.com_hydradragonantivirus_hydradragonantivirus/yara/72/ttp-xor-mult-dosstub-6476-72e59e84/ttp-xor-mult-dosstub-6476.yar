rule TTP_XOR_MULT_DOSStub_6476 {
  strings:
    $key_6476 = { 30 1e [2] 44 06 [2] 03 04 [2] 44 15 [2] 0a 19 [2] 06 13 [2] 11 18 [2] 0a 56 [2] 37 }

  condition:
    any of them
}