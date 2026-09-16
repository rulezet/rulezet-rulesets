rule TTP_XOR_MULT_DOSStub_b5f9 {
  strings:
    $key_b5f9 = { e1 91 [2] 95 89 [2] d2 8b [2] 95 9a [2] db 96 [2] d7 9c [2] c0 97 [2] db d9 [2] e6 }

  condition:
    any of them
}