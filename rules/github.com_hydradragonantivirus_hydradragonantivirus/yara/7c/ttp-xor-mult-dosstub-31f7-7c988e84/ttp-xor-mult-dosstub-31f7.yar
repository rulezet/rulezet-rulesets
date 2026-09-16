rule TTP_XOR_MULT_DOSStub_31f7 {
  strings:
    $key_31f7 = { 65 9f [2] 11 87 [2] 56 85 [2] 11 94 [2] 5f 98 [2] 53 92 [2] 44 99 [2] 5f d7 [2] 62 }

  condition:
    any of them
}