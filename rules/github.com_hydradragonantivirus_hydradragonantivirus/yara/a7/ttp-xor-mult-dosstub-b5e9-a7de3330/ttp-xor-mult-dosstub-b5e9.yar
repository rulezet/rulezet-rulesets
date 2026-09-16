rule TTP_XOR_MULT_DOSStub_b5e9 {
  strings:
    $key_b5e9 = { e1 81 [2] 95 99 [2] d2 9b [2] 95 8a [2] db 86 [2] d7 8c [2] c0 87 [2] db c9 [2] e6 }

  condition:
    any of them
}