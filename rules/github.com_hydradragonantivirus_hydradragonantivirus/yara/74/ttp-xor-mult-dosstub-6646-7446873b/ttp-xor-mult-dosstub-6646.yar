rule TTP_XOR_MULT_DOSStub_6646 {
  strings:
    $key_6646 = { 32 2e [2] 46 36 [2] 01 34 [2] 46 25 [2] 08 29 [2] 04 23 [2] 13 28 [2] 08 66 [2] 35 }

  condition:
    any of them
}