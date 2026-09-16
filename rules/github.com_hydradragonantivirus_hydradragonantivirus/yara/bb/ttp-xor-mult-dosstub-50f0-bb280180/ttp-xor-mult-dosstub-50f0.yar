rule TTP_XOR_MULT_DOSStub_50f0 {
  strings:
    $key_50f0 = { 04 98 [2] 70 80 [2] 37 82 [2] 70 93 [2] 3e 9f [2] 32 95 [2] 25 9e [2] 3e d0 [2] 03 }

  condition:
    any of them
}