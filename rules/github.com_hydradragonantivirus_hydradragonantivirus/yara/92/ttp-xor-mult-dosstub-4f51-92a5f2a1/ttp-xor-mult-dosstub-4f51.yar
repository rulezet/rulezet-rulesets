rule TTP_XOR_MULT_DOSStub_4f51 {
  strings:
    $key_4f51 = { 1b 39 [2] 6f 21 [2] 28 23 [2] 6f 32 [2] 21 3e [2] 2d 34 [2] 3a 3f [2] 21 71 [2] 1c }

  condition:
    any of them
}