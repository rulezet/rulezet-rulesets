rule TTP_XOR_MULT_DOSStub_67f1 {
  strings:
    $key_67f1 = { 33 99 [2] 47 81 [2] 00 83 [2] 47 92 [2] 09 9e [2] 05 94 [2] 12 9f [2] 09 d1 [2] 34 }

  condition:
    any of them
}