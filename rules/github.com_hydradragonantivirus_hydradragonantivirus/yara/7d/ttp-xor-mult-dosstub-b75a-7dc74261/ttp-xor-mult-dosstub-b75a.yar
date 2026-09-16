rule TTP_XOR_MULT_DOSStub_b75a {
  strings:
    $key_b75a = { e3 32 [2] 97 2a [2] d0 28 [2] 97 39 [2] d9 35 [2] d5 3f [2] c2 34 [2] d9 7a [2] e4 }

  condition:
    any of them
}