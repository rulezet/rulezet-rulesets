rule TTP_XOR_MULT_DOSStub_51f0 {
  strings:
    $key_51f0 = { 05 98 [2] 71 80 [2] 36 82 [2] 71 93 [2] 3f 9f [2] 33 95 [2] 24 9e [2] 3f d0 [2] 02 }

  condition:
    any of them
}