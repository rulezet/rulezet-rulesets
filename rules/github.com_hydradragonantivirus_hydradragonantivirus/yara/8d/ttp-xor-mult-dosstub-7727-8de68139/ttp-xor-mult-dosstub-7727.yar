rule TTP_XOR_MULT_DOSStub_7727 {
  strings:
    $key_7727 = { 23 4f [2] 57 57 [2] 10 55 [2] 57 44 [2] 19 48 [2] 15 42 [2] 02 49 [2] 19 07 [2] 24 }

  condition:
    any of them
}