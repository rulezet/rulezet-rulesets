rule TTP_XOR_MULT_DOSStub_b00b {
  strings:
    $key_b00b = { e4 63 [2] 90 7b [2] d7 79 [2] 90 68 [2] de 64 [2] d2 6e [2] c5 65 [2] de 2b [2] e3 }

  condition:
    any of them
}