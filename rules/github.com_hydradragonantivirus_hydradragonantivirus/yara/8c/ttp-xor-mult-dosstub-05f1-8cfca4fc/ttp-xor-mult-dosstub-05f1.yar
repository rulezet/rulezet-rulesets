rule TTP_XOR_MULT_DOSStub_05f1 {
  strings:
    $key_05f1 = { 51 99 [2] 25 81 [2] 62 83 [2] 25 92 [2] 6b 9e [2] 67 94 [2] 70 9f [2] 6b d1 [2] 56 }

  condition:
    any of them
}