rule TTP_XOR_MULT_DOSStub_b576 {
  strings:
    $key_b576 = { e1 1e [2] 95 06 [2] d2 04 [2] 95 15 [2] db 19 [2] d7 13 [2] c0 18 [2] db 56 [2] e6 }

  condition:
    any of them
}