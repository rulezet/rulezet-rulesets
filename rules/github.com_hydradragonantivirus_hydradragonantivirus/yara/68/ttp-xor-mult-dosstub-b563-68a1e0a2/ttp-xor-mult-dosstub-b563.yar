rule TTP_XOR_MULT_DOSStub_b563 {
  strings:
    $key_b563 = { e1 0b [2] 95 13 [2] d2 11 [2] 95 00 [2] db 0c [2] d7 06 [2] c0 0d [2] db 43 [2] e6 }

  condition:
    any of them
}