rule TTP_XOR_MULT_DOSStub_05f7 {
  strings:
    $key_05f7 = { 51 9f [2] 25 87 [2] 62 85 [2] 25 94 [2] 6b 98 [2] 67 92 [2] 70 99 [2] 6b d7 [2] 56 }

  condition:
    any of them
}