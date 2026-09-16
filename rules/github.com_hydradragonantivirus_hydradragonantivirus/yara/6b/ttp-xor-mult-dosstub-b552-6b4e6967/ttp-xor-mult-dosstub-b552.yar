rule TTP_XOR_MULT_DOSStub_b552 {
  strings:
    $key_b552 = { e1 3a [2] 95 22 [2] d2 20 [2] 95 31 [2] db 3d [2] d7 37 [2] c0 3c [2] db 72 [2] e6 }

  condition:
    any of them
}