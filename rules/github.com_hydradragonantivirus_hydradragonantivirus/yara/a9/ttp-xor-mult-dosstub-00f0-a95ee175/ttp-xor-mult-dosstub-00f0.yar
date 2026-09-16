rule TTP_XOR_MULT_DOSStub_00f0 {
  strings:
    $key_00f0 = { 54 98 [2] 20 80 [2] 67 82 [2] 20 93 [2] 6e 9f [2] 62 95 [2] 75 9e [2] 6e d0 [2] 53 }

  condition:
    any of them
}