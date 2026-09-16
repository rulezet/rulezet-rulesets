rule TTP_XOR_MULT_DOSStub_4525 {
  strings:
    $key_4525 = { 11 4d [2] 65 55 [2] 22 57 [2] 65 46 [2] 2b 4a [2] 27 40 [2] 30 4b [2] 2b 05 [2] 16 }

  condition:
    any of them
}