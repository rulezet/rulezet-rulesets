rule TTP_XOR_MULT_DOSStub_b37f {
  strings:
    $key_b37f = { e7 17 [2] 93 0f [2] d4 0d [2] 93 1c [2] dd 10 [2] d1 1a [2] c6 11 [2] dd 5f [2] e0 }

  condition:
    any of them
}