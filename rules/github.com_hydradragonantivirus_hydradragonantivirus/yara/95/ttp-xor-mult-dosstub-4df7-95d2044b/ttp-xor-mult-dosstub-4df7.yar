rule TTP_XOR_MULT_DOSStub_4df7 {
  strings:
    $key_4df7 = { 19 9f [2] 6d 87 [2] 2a 85 [2] 6d 94 [2] 23 98 [2] 2f 92 [2] 38 99 [2] 23 d7 [2] 1e }

  condition:
    any of them
}