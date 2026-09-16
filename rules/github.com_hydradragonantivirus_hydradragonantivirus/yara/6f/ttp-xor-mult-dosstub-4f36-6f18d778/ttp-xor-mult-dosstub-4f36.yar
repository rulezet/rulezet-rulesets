rule TTP_XOR_MULT_DOSStub_4f36 {
  strings:
    $key_4f36 = { 1b 5e [2] 6f 46 [2] 28 44 [2] 6f 55 [2] 21 59 [2] 2d 53 [2] 3a 58 [2] 21 16 [2] 1c }

  condition:
    any of them
}