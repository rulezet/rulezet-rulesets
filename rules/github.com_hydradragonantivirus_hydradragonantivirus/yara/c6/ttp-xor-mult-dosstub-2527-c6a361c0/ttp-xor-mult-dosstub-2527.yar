rule TTP_XOR_MULT_DOSStub_2527 {
  strings:
    $key_2527 = { 71 4f [2] 05 57 [2] 42 55 [2] 05 44 [2] 4b 48 [2] 47 42 [2] 50 49 [2] 4b 07 [2] 76 }

  condition:
    any of them
}