rule TTP_XOR_MULT_DOSStub_35f1 {
  strings:
    $key_35f1 = { 61 99 [2] 15 81 [2] 52 83 [2] 15 92 [2] 5b 9e [2] 57 94 [2] 40 9f [2] 5b d1 [2] 66 }

  condition:
    any of them
}