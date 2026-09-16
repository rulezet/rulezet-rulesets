rule TTP_XOR_MULT_DOSStub_3df1 {
  strings:
    $key_3df1 = { 69 99 [2] 1d 81 [2] 5a 83 [2] 1d 92 [2] 53 9e [2] 5f 94 [2] 48 9f [2] 53 d1 [2] 6e }

  condition:
    any of them
}