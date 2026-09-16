rule TTP_XOR_MULT_DOSStub_7626 {
  strings:
    $key_7626 = { 22 4e [2] 56 56 [2] 11 54 [2] 56 45 [2] 18 49 [2] 14 43 [2] 03 48 [2] 18 06 [2] 25 }

  condition:
    any of them
}