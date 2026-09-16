rule TTP_XOR_MULT_DOSStub_2df7 {
  strings:
    $key_2df7 = { 79 9f [2] 0d 87 [2] 4a 85 [2] 0d 94 [2] 43 98 [2] 4f 92 [2] 58 99 [2] 43 d7 [2] 7e }

  condition:
    any of them
}