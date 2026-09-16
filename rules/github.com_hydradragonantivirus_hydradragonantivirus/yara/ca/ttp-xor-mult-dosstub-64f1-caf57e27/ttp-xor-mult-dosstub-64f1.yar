rule TTP_XOR_MULT_DOSStub_64f1 {
  strings:
    $key_64f1 = { 30 99 [2] 44 81 [2] 03 83 [2] 44 92 [2] 0a 9e [2] 06 94 [2] 11 9f [2] 0a d1 [2] 37 }

  condition:
    any of them
}