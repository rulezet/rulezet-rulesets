rule TTP_XOR_MULT_DOSStub_b33a {
  strings:
    $key_b33a = { e7 52 [2] 93 4a [2] d4 48 [2] 93 59 [2] dd 55 [2] d1 5f [2] c6 54 [2] dd 1a [2] e0 }

  condition:
    any of them
}