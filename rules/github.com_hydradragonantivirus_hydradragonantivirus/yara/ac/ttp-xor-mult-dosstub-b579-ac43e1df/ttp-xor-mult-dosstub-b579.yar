rule TTP_XOR_MULT_DOSStub_b579 {
  strings:
    $key_b579 = { e1 11 [2] 95 09 [2] d2 0b [2] 95 1a [2] db 16 [2] d7 1c [2] c0 17 [2] db 59 [2] e6 }

  condition:
    any of them
}