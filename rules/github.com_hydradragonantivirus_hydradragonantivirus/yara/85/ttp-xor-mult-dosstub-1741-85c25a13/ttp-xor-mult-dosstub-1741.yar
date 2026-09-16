rule TTP_XOR_MULT_DOSStub_1741 {
  strings:
    $key_1741 = { 43 29 [2] 37 31 [2] 70 33 [2] 37 22 [2] 79 2e [2] 75 24 [2] 62 2f [2] 79 61 [2] 44 }

  condition:
    any of them
}