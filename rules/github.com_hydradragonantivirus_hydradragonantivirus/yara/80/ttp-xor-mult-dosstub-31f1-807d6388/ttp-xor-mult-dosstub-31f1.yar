rule TTP_XOR_MULT_DOSStub_31f1 {
  strings:
    $key_31f1 = { 65 99 [2] 11 81 [2] 56 83 [2] 11 92 [2] 5f 9e [2] 53 94 [2] 44 9f [2] 5f d1 [2] 62 }

  condition:
    any of them
}