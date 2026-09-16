rule TTP_XOR_MULT_DOSStub_4747 {
  strings:
    $key_4747 = { 13 2f [2] 67 37 [2] 20 35 [2] 67 24 [2] 29 28 [2] 25 22 [2] 32 29 [2] 29 67 [2] 14 }

  condition:
    any of them
}