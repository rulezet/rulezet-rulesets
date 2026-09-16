rule TTP_XOR_MULT_DOSStub_4477 {
  strings:
    $key_4477 = { 10 1f [2] 64 07 [2] 23 05 [2] 64 14 [2] 2a 18 [2] 26 12 [2] 31 19 [2] 2a 57 [2] 17 }

  condition:
    any of them
}