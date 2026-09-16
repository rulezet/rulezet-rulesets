rule TTP_XOR_MULT_DOSStub_55f1 {
  strings:
    $key_55f1 = { 01 99 [2] 75 81 [2] 32 83 [2] 75 92 [2] 3b 9e [2] 37 94 [2] 20 9f [2] 3b d1 [2] 06 }

  condition:
    any of them
}