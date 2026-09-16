rule TTP_XOR_MULT_DOSStub_3547 {
  strings:
    $key_3547 = { 61 2f [2] 15 37 [2] 52 35 [2] 15 24 [2] 5b 28 [2] 57 22 [2] 40 29 [2] 5b 67 [2] 66 }

  condition:
    any of them
}