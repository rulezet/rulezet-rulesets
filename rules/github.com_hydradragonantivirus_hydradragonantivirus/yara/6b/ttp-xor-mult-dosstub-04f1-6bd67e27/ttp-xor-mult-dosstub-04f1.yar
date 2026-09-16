rule TTP_XOR_MULT_DOSStub_04f1 {
  strings:
    $key_04f1 = { 50 99 [2] 24 81 [2] 63 83 [2] 24 92 [2] 6a 9e [2] 66 94 [2] 71 9f [2] 6a d1 [2] 57 }

  condition:
    any of them
}