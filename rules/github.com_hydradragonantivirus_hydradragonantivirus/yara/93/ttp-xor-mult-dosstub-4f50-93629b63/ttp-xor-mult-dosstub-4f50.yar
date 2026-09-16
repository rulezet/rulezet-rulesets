rule TTP_XOR_MULT_DOSStub_4f50 {
  strings:
    $key_4f50 = { 1b 38 [2] 6f 20 [2] 28 22 [2] 6f 33 [2] 21 3f [2] 2d 35 [2] 3a 3e [2] 21 70 [2] 1c }

  condition:
    any of them
}