rule TTP_XOR_MULT_DOSStub_27f1 {
  strings:
    $key_27f1 = { 73 99 [2] 07 81 [2] 40 83 [2] 07 92 [2] 49 9e [2] 45 94 [2] 52 9f [2] 49 d1 [2] 74 }

  condition:
    any of them
}