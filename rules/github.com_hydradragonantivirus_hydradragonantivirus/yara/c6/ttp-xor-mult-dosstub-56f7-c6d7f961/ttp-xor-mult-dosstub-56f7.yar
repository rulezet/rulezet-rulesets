rule TTP_XOR_MULT_DOSStub_56f7 {
  strings:
    $key_56f7 = { 02 9f [2] 76 87 [2] 31 85 [2] 76 94 [2] 38 98 [2] 34 92 [2] 23 99 [2] 38 d7 [2] 05 }

  condition:
    any of them
}