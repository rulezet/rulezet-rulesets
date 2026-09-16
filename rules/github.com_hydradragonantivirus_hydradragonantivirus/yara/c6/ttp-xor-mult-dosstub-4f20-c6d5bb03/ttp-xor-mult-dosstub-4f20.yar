rule TTP_XOR_MULT_DOSStub_4f20 {
  strings:
    $key_4f20 = { 1b 48 [2] 6f 50 [2] 28 52 [2] 6f 43 [2] 21 4f [2] 2d 45 [2] 3a 4e [2] 21 00 [2] 1c }

  condition:
    any of them
}