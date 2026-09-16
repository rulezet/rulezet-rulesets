rule TTP_XOR_MULT_DOSStub_74f0 {
  strings:
    $key_74f0 = { 20 98 [2] 54 80 [2] 13 82 [2] 54 93 [2] 1a 9f [2] 16 95 [2] 01 9e [2] 1a d0 [2] 27 }

  condition:
    any of them
}