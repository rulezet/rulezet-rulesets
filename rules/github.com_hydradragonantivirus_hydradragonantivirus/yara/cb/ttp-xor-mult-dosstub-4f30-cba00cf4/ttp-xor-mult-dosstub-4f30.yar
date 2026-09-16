rule TTP_XOR_MULT_DOSStub_4f30 {
  strings:
    $key_4f30 = { 1b 58 [2] 6f 40 [2] 28 42 [2] 6f 53 [2] 21 5f [2] 2d 55 [2] 3a 5e [2] 21 10 [2] 1c }

  condition:
    any of them
}