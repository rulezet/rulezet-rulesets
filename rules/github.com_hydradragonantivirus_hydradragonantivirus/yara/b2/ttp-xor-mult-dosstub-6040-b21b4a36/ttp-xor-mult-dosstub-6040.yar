rule TTP_XOR_MULT_DOSStub_6040 {
  strings:
    $key_6040 = { 34 28 [2] 40 30 [2] 07 32 [2] 40 23 [2] 0e 2f [2] 02 25 [2] 15 2e [2] 0e 60 [2] 33 }

  condition:
    any of them
}