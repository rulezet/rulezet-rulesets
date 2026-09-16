rule TTP_XOR_MULT_DOSStub_72f0 {
  strings:
    $key_72f0 = { 26 98 [2] 52 80 [2] 15 82 [2] 52 93 [2] 1c 9f [2] 10 95 [2] 07 9e [2] 1c d0 [2] 21 }

  condition:
    any of them
}