rule TTP_XOR_MULT_DOSStub_12f0 {
  strings:
    $key_12f0 = { 46 98 [2] 32 80 [2] 75 82 [2] 32 93 [2] 7c 9f [2] 70 95 [2] 67 9e [2] 7c d0 [2] 41 }

  condition:
    any of them
}