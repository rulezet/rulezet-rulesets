rule TTP_XOR_MULT_DOSStub_3bf7 {
  strings:
    $key_3bf7 = { 6f 9f [2] 1b 87 [2] 5c 85 [2] 1b 94 [2] 55 98 [2] 59 92 [2] 4e 99 [2] 55 d7 [2] 68 }

  condition:
    any of them
}