rule TTP_XOR_MULT_DOSStub_b566 {
  strings:
    $key_b566 = { e1 0e [2] 95 16 [2] d2 14 [2] 95 05 [2] db 09 [2] d7 03 [2] c0 08 [2] db 46 [2] e6 }

  condition:
    any of them
}