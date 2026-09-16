rule TTP_XOR_MULT_DOSStub_0441 {
  strings:
    $key_0441 = { 50 29 [2] 24 31 [2] 63 33 [2] 24 22 [2] 6a 2e [2] 66 24 [2] 71 2f [2] 6a 61 [2] 57 }

  condition:
    any of them
}