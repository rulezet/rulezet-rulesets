rule TTP_XOR_MULT_DOSStub_4fe6 {
  strings:
    $key_4fe6 = { 1b 8e [2] 6f 96 [2] 28 94 [2] 6f 85 [2] 21 89 [2] 2d 83 [2] 3a 88 [2] 21 c6 [2] 1c }

  condition:
    any of them
}