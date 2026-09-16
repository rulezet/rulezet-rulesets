rule TTP_XOR_MULT_DOSStub_b35f {
  strings:
    $key_b35f = { e7 37 [2] 93 2f [2] d4 2d [2] 93 3c [2] dd 30 [2] d1 3a [2] c6 31 [2] dd 7f [2] e0 }

  condition:
    any of them
}