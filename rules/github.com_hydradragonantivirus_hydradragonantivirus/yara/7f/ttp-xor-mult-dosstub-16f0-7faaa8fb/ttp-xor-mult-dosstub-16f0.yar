rule TTP_XOR_MULT_DOSStub_16f0 {
  strings:
    $key_16f0 = { 42 98 [2] 36 80 [2] 71 82 [2] 36 93 [2] 78 9f [2] 74 95 [2] 63 9e [2] 78 d0 [2] 45 }

  condition:
    any of them
}