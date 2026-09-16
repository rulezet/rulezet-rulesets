rule TTP_XOR_MULT_DOSStub_7427 {
  strings:
    $key_7427 = { 20 4f [2] 54 57 [2] 13 55 [2] 54 44 [2] 1a 48 [2] 16 42 [2] 01 49 [2] 1a 07 [2] 27 }

  condition:
    any of them
}