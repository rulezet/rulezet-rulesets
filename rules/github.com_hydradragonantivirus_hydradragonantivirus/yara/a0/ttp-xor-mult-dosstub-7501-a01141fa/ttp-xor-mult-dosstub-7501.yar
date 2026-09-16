rule TTP_XOR_MULT_DOSStub_7501 {
  strings:
    $key_7501 = { 21 69 [2] 55 71 [2] 12 73 [2] 55 62 [2] 1b 6e [2] 17 64 [2] 00 6f [2] 1b 21 [2] 26 }

  condition:
    any of them
}