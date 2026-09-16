rule TTP_XOR_MULT_DOSStub_45f0 {
  strings:
    $key_45f0 = { 11 98 [2] 65 80 [2] 22 82 [2] 65 93 [2] 2b 9f [2] 27 95 [2] 30 9e [2] 2b d0 [2] 16 }

  condition:
    any of them
}