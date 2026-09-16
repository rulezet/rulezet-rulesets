rule TTP_XOR_MULT_DOSStub_4ff1 {
  strings:
    $key_4ff1 = { 1b 99 [2] 6f 81 [2] 28 83 [2] 6f 92 [2] 21 9e [2] 2d 94 [2] 3a 9f [2] 21 d1 [2] 1c }

  condition:
    any of them
}