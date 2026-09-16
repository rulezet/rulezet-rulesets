rule TTP_XOR_MULT_DOSStub_b568 {
  strings:
    $key_b568 = { e1 00 [2] 95 18 [2] d2 1a [2] 95 0b [2] db 07 [2] d7 0d [2] c0 06 [2] db 48 [2] e6 }

  condition:
    any of them
}