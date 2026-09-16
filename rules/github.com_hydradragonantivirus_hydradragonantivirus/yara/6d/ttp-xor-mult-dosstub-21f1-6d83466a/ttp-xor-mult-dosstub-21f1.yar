rule TTP_XOR_MULT_DOSStub_21f1 {
  strings:
    $key_21f1 = { 75 99 [2] 01 81 [2] 46 83 [2] 01 92 [2] 4f 9e [2] 43 94 [2] 54 9f [2] 4f d1 [2] 72 }

  condition:
    any of them
}