rule TTP_XOR_MULT_DOSStub_b572 {
  strings:
    $key_b572 = { e1 1a [2] 95 02 [2] d2 00 [2] 95 11 [2] db 1d [2] d7 17 [2] c0 1c [2] db 52 [2] e6 }

  condition:
    any of them
}