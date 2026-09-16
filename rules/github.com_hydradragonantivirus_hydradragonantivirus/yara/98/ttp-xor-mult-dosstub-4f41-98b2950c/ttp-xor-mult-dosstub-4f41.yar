rule TTP_XOR_MULT_DOSStub_4f41 {
  strings:
    $key_4f41 = { 1b 29 [2] 6f 31 [2] 28 33 [2] 6f 22 [2] 21 2e [2] 2d 24 [2] 3a 2f [2] 21 61 [2] 1c }

  condition:
    any of them
}