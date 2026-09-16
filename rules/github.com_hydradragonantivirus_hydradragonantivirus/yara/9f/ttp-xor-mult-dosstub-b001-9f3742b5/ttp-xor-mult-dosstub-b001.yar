rule TTP_XOR_MULT_DOSStub_b001 {
  strings:
    $key_b001 = { e4 69 [2] 90 71 [2] d7 73 [2] 90 62 [2] de 6e [2] d2 64 [2] c5 6f [2] de 21 [2] e3 }

  condition:
    any of them
}