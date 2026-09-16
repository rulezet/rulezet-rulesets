rule TTP_XOR_MULT_DOSStub_4df1 {
  strings:
    $key_4df1 = { 19 99 [2] 6d 81 [2] 2a 83 [2] 6d 92 [2] 23 9e [2] 2f 94 [2] 38 9f [2] 23 d1 [2] 1e }

  condition:
    any of them
}