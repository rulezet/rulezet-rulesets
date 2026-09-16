rule TTP_XOR_MULT_DOSStub_b548 {
  strings:
    $key_b548 = { e1 20 [2] 95 38 [2] d2 3a [2] 95 2b [2] db 27 [2] d7 2d [2] c0 26 [2] db 68 [2] e6 }

  condition:
    any of them
}