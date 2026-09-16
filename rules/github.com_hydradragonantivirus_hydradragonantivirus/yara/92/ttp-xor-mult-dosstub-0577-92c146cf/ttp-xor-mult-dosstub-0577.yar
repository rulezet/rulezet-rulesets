rule TTP_XOR_MULT_DOSStub_0577 {
  strings:
    $key_0577 = { 51 1f [2] 25 07 [2] 62 05 [2] 25 14 [2] 6b 18 [2] 67 12 [2] 70 19 [2] 6b 57 [2] 56 }

  condition:
    any of them
}