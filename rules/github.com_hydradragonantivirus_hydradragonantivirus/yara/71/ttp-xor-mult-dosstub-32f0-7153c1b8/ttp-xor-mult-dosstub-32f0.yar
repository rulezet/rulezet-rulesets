rule TTP_XOR_MULT_DOSStub_32f0 {
  strings:
    $key_32f0 = { 66 98 [2] 12 80 [2] 55 82 [2] 12 93 [2] 5c 9f [2] 50 95 [2] 47 9e [2] 5c d0 [2] 61 }

  condition:
    any of them
}