rule TTP_XOR_MULT_DOSStub_65f7 {
  strings:
    $key_65f7 = { 31 9f [2] 45 87 [2] 02 85 [2] 45 94 [2] 0b 98 [2] 07 92 [2] 10 99 [2] 0b d7 [2] 36 }

  condition:
    any of them
}