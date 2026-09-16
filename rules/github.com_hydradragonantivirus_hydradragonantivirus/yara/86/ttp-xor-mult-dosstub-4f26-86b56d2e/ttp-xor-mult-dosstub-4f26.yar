rule TTP_XOR_MULT_DOSStub_4f26 {
  strings:
    $key_4f26 = { 1b 4e [2] 6f 56 [2] 28 54 [2] 6f 45 [2] 21 49 [2] 2d 43 [2] 3a 48 [2] 21 06 [2] 1c }

  condition:
    any of them
}