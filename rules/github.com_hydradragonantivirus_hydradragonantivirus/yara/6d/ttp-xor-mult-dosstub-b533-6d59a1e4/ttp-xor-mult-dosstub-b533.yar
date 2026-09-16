rule TTP_XOR_MULT_DOSStub_b533 {
  strings:
    $key_b533 = { e1 5b [2] 95 43 [2] d2 41 [2] 95 50 [2] db 5c [2] d7 56 [2] c0 5d [2] db 13 [2] e6 }

  condition:
    any of them
}