rule TTP_XOR_MULT_DOSStub_17f0 {
  strings:
    $key_17f0 = { 43 98 [2] 37 80 [2] 70 82 [2] 37 93 [2] 79 9f [2] 75 95 [2] 62 9e [2] 79 d0 [2] 44 }

  condition:
    any of them
}