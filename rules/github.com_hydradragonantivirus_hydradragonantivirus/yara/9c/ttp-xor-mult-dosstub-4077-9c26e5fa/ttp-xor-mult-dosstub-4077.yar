rule TTP_XOR_MULT_DOSStub_4077 {
  strings:
    $key_4077 = { 14 1f [2] 60 07 [2] 27 05 [2] 60 14 [2] 2e 18 [2] 22 12 [2] 35 19 [2] 2e 57 [2] 13 }

  condition:
    any of them
}