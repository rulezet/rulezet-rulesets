rule TTP_XOR_MULT_DOSStub_4f16 {
  strings:
    $key_4f16 = { 1b 7e [2] 6f 66 [2] 28 64 [2] 6f 75 [2] 21 79 [2] 2d 73 [2] 3a 78 [2] 21 36 [2] 1c }

  condition:
    any of them
}