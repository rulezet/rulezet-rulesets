rule TTP_XOR_MULT_DOSStub_52f7 {
  strings:
    $key_52f7 = { 06 9f [2] 72 87 [2] 35 85 [2] 72 94 [2] 3c 98 [2] 30 92 [2] 27 99 [2] 3c d7 [2] 01 }

  condition:
    any of them
}