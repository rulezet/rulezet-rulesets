rule TTP_XOR_MULT_DOSStub_4f47 {
  strings:
    $key_4f47 = { 1b 2f [2] 6f 37 [2] 28 35 [2] 6f 24 [2] 21 28 [2] 2d 22 [2] 3a 29 [2] 21 67 [2] 1c }

  condition:
    any of them
}