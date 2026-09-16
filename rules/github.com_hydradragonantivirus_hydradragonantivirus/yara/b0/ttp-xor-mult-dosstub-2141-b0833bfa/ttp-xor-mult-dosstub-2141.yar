rule TTP_XOR_MULT_DOSStub_2141 {
  strings:
    $key_2141 = { 75 29 [2] 01 31 [2] 46 33 [2] 01 22 [2] 4f 2e [2] 43 24 [2] 54 2f [2] 4f 61 [2] 72 }

  condition:
    any of them
}