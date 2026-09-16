rule TTP_XOR_MULT_DOSStub_4f27 {
  strings:
    $key_4f27 = { 1b 4f [2] 6f 57 [2] 28 55 [2] 6f 44 [2] 21 48 [2] 2d 42 [2] 3a 49 [2] 21 07 [2] 1c }

  condition:
    any of them
}