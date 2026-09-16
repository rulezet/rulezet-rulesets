rule TTP_XOR_MULT_DOSStub_1bf7 {
  strings:
    $key_1bf7 = { 4f 9f [2] 3b 87 [2] 7c 85 [2] 3b 94 [2] 75 98 [2] 79 92 [2] 6e 99 [2] 75 d7 [2] 48 }

  condition:
    any of them
}