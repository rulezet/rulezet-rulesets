rule TTP_XOR_MULT_DOSStub_4ff0 {
  strings:
    $key_4ff0 = { 1b 98 [2] 6f 80 [2] 28 82 [2] 6f 93 [2] 21 9f [2] 2d 95 [2] 3a 9e [2] 21 d0 [2] 1c }

  condition:
    any of them
}