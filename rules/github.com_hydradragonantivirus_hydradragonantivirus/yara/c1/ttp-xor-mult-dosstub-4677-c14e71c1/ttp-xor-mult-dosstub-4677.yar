rule TTP_XOR_MULT_DOSStub_4677 {
  strings:
    $key_4677 = { 12 1f [2] 66 07 [2] 21 05 [2] 66 14 [2] 28 18 [2] 24 12 [2] 33 19 [2] 28 57 [2] 15 }

  condition:
    any of them
}