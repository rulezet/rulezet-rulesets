rule TTP_XOR_MULT_DOSStub_4f56 {
  strings:
    $key_4f56 = { 1b 3e [2] 6f 26 [2] 28 24 [2] 6f 35 [2] 21 39 [2] 2d 33 [2] 3a 38 [2] 21 76 [2] 1c }

  condition:
    any of them
}