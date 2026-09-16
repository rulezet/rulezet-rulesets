rule TTP_XOR_MULT_DOSStub_b51f {
  strings:
    $key_b51f = { e1 77 [2] 95 6f [2] d2 6d [2] 95 7c [2] db 70 [2] d7 7a [2] c0 71 [2] db 3f [2] e6 }

  condition:
    any of them
}