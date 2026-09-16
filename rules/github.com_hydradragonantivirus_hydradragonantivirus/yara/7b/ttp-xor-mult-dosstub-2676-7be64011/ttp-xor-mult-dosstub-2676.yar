rule TTP_XOR_MULT_DOSStub_2676 {
  strings:
    $key_2676 = { 72 1e [2] 06 06 [2] 41 04 [2] 06 15 [2] 48 19 [2] 44 13 [2] 53 18 [2] 48 56 [2] 75 }

  condition:
    any of them
}