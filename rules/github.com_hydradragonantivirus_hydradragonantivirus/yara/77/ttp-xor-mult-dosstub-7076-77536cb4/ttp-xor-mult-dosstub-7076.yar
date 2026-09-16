rule TTP_XOR_MULT_DOSStub_7076 {
  strings:
    $key_7076 = { 24 1e [2] 50 06 [2] 17 04 [2] 50 15 [2] 1e 19 [2] 12 13 [2] 05 18 [2] 1e 56 [2] 23 }

  condition:
    any of them
}