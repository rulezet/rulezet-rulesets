rule TTP_XOR_MULT_DOSStub_b524 {
  strings:
    $key_b524 = { e1 4c [2] 95 54 [2] d2 56 [2] 95 47 [2] db 4b [2] d7 41 [2] c0 4a [2] db 04 [2] e6 }

  condition:
    any of them
}