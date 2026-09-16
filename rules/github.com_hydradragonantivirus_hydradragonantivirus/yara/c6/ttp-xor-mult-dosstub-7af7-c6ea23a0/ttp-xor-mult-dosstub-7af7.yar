rule TTP_XOR_MULT_DOSStub_7af7 {
  strings:
    $key_7af7 = { 2e 9f [2] 5a 87 [2] 1d 85 [2] 5a 94 [2] 14 98 [2] 18 92 [2] 0f 99 [2] 14 d7 [2] 29 }

  condition:
    any of them
}