rule TTP_XOR_MULT_DOSStub_4f01 {
  strings:
    $key_4f01 = { 1b 69 [2] 6f 71 [2] 28 73 [2] 6f 62 [2] 21 6e [2] 2d 64 [2] 3a 6f [2] 21 21 [2] 1c }

  condition:
    any of them
}