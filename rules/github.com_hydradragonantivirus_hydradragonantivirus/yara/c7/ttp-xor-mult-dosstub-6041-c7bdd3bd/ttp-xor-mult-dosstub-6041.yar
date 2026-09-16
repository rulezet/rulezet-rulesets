rule TTP_XOR_MULT_DOSStub_6041 {
  strings:
    $key_6041 = { 34 29 [2] 40 31 [2] 07 33 [2] 40 22 [2] 0e 2e [2] 02 24 [2] 15 2f [2] 0e 61 [2] 33 }

  condition:
    any of them
}