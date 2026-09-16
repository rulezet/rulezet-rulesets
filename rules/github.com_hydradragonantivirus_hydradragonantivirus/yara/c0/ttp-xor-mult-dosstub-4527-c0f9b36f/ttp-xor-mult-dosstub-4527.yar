rule TTP_XOR_MULT_DOSStub_4527 {
  strings:
    $key_4527 = { 11 4f [2] 65 57 [2] 22 55 [2] 65 44 [2] 2b 48 [2] 27 42 [2] 30 49 [2] 2b 07 [2] 16 }

  condition:
    any of them
}