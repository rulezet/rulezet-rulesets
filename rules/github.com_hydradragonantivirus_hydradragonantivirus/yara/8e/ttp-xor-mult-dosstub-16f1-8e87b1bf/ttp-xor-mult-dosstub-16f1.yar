rule TTP_XOR_MULT_DOSStub_16f1 {
  strings:
    $key_16f1 = { 42 99 [2] 36 81 [2] 71 83 [2] 36 92 [2] 78 9e [2] 74 94 [2] 63 9f [2] 78 d1 [2] 45 }

  condition:
    any of them
}