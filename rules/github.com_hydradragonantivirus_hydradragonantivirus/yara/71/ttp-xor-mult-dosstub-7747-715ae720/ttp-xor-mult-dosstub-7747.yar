rule TTP_XOR_MULT_DOSStub_7747 {
  strings:
    $key_7747 = { 23 2f [2] 57 37 [2] 10 35 [2] 57 24 [2] 19 28 [2] 15 22 [2] 02 29 [2] 19 67 [2] 24 }

  condition:
    any of them
}