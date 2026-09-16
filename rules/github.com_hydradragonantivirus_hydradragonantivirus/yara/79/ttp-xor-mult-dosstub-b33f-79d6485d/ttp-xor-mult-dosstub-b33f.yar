rule TTP_XOR_MULT_DOSStub_b33f {
  strings:
    $key_b33f = { e7 57 [2] 93 4f [2] d4 4d [2] 93 5c [2] dd 50 [2] d1 5a [2] c6 51 [2] dd 1f [2] e0 }

  condition:
    any of them
}