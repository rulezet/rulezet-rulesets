rule TTP_XOR_MULT_DOSStub_1727 {
  strings:
    $key_1727 = { 43 4f [2] 37 57 [2] 70 55 [2] 37 44 [2] 79 48 [2] 75 42 [2] 62 49 [2] 79 07 [2] 44 }

  condition:
    any of them
}