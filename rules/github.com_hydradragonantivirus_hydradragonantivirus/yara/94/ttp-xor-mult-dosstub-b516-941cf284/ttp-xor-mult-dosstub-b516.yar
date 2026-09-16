rule TTP_XOR_MULT_DOSStub_b516 {
  strings:
    $key_b516 = { e1 7e [2] 95 66 [2] d2 64 [2] 95 75 [2] db 79 [2] d7 73 [2] c0 78 [2] db 36 [2] e6 }

  condition:
    any of them
}