rule TTP_XOR_MULT_DOSStub_b311 {
  strings:
    $key_b311 = { e7 79 [2] 93 61 [2] d4 63 [2] 93 72 [2] dd 7e [2] d1 74 [2] c6 7f [2] dd 31 [2] e0 }

  condition:
    any of them
}