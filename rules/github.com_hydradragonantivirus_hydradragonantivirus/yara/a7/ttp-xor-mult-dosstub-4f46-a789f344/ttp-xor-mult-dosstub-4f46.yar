rule TTP_XOR_MULT_DOSStub_4f46 {
  strings:
    $key_4f46 = { 1b 2e [2] 6f 36 [2] 28 34 [2] 6f 25 [2] 21 29 [2] 2d 23 [2] 3a 28 [2] 21 66 [2] 1c }

  condition:
    any of them
}