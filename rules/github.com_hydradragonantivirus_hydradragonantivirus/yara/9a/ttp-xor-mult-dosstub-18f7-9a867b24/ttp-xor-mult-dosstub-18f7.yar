rule TTP_XOR_MULT_DOSStub_18f7 {
  strings:
    $key_18f7 = { 4c 9f [2] 38 87 [2] 7f 85 [2] 38 94 [2] 76 98 [2] 7a 92 [2] 6d 99 [2] 76 d7 [2] 4b }

  condition:
    any of them
}