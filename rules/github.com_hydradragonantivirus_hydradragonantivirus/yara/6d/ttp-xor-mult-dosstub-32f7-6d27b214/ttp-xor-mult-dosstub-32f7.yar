rule TTP_XOR_MULT_DOSStub_32f7 {
  strings:
    $key_32f7 = { 66 9f [2] 12 87 [2] 55 85 [2] 12 94 [2] 5c 98 [2] 50 92 [2] 47 99 [2] 5c d7 [2] 61 }

  condition:
    any of them
}