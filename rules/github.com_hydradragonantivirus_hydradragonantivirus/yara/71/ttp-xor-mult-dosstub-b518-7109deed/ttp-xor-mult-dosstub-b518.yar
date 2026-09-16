rule TTP_XOR_MULT_DOSStub_b518 {
  strings:
    $key_b518 = { e1 70 [2] 95 68 [2] d2 6a [2] 95 7b [2] db 77 [2] d7 7d [2] c0 76 [2] db 38 [2] e6 }

  condition:
    any of them
}