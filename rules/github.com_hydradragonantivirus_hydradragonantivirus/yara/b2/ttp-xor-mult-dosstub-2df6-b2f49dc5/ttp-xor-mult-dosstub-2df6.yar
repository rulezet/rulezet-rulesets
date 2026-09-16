rule TTP_XOR_MULT_DOSStub_2df6 {
  strings:
    $key_2df6 = { 79 9e [2] 0d 86 [2] 4a 84 [2] 0d 95 [2] 43 99 [2] 4f 93 [2] 58 98 [2] 43 d6 [2] 7e }

  condition:
    any of them
}