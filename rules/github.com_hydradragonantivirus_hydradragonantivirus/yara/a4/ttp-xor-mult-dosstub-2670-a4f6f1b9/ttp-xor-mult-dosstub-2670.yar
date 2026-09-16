rule TTP_XOR_MULT_DOSStub_2670 {
  strings:
    $key_2670 = { 72 18 [2] 06 00 [2] 41 02 [2] 06 13 [2] 48 1f [2] 44 15 [2] 53 1e [2] 48 50 [2] 75 }

  condition:
    any of them
}