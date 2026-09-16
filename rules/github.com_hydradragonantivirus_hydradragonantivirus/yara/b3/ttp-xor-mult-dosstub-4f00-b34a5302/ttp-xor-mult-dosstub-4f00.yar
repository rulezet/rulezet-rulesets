rule TTP_XOR_MULT_DOSStub_4f00 {
  strings:
    $key_4f00 = { 1b 68 [2] 6f 70 [2] 28 72 [2] 6f 63 [2] 21 6f [2] 2d 65 [2] 3a 6e [2] 21 20 [2] 1c }

  condition:
    any of them
}