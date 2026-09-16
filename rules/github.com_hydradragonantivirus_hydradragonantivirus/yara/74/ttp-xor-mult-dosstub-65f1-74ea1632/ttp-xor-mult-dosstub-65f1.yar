rule TTP_XOR_MULT_DOSStub_65f1 {
  strings:
    $key_65f1 = { 31 99 [2] 45 81 [2] 02 83 [2] 45 92 [2] 0b 9e [2] 07 94 [2] 10 9f [2] 0b d1 [2] 36 }

  condition:
    any of them
}