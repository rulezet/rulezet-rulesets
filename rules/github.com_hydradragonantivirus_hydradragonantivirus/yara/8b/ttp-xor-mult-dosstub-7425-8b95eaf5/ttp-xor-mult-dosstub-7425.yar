rule TTP_XOR_MULT_DOSStub_7425 {
  strings:
    $key_7425 = { 20 4d [2] 54 55 [2] 13 57 [2] 54 46 [2] 1a 4a [2] 16 40 [2] 01 4b [2] 1a 05 [2] 27 }

  condition:
    any of them
}