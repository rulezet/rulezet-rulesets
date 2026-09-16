rule TTP_XOR_MULT_DOSStub_77f1 {
  strings:
    $key_77f1 = { 23 99 [2] 57 81 [2] 10 83 [2] 57 92 [2] 19 9e [2] 15 94 [2] 02 9f [2] 19 d1 [2] 24 }

  condition:
    any of them
}