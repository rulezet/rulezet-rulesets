rule TTP_XOR_MULT_DOSStub_51f6 {
  strings:
    $key_51f6 = { 05 9e [2] 71 86 [2] 36 84 [2] 71 95 [2] 3f 99 [2] 33 93 [2] 24 98 [2] 3f d6 [2] 02 }

  condition:
    any of them
}