rule TTP_XOR_MULT_DOSStub_4076 {
  strings:
    $key_4076 = { 14 1e [2] 60 06 [2] 27 04 [2] 60 15 [2] 2e 19 [2] 22 13 [2] 35 18 [2] 2e 56 [2] 13 }

  condition:
    any of them
}