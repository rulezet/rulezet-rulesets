rule TTP_XOR_MULT_DOSStub_b51b {
  strings:
    $key_b51b = { e1 73 [2] 95 6b [2] d2 69 [2] 95 78 [2] db 74 [2] d7 7e [2] c0 75 [2] db 3b [2] e6 }

  condition:
    any of them
}