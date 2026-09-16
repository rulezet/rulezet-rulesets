rule TTP_XOR_MULT_DOSStub_26f7 {
  strings:
    $key_26f7 = { 72 9f [2] 06 87 [2] 41 85 [2] 06 94 [2] 48 98 [2] 44 92 [2] 53 99 [2] 48 d7 [2] 75 }

  condition:
    any of them
}