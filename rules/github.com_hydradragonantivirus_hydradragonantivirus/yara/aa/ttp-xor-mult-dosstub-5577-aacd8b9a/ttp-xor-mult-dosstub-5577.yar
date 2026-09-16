rule TTP_XOR_MULT_DOSStub_5577 {
  strings:
    $key_5577 = { 01 1f [2] 75 07 [2] 32 05 [2] 75 14 [2] 3b 18 [2] 37 12 [2] 20 19 [2] 3b 57 [2] 06 }

  condition:
    any of them
}