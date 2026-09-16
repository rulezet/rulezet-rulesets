rule TTP_XOR_MULT_DOSStub_b65d {
  strings:
    $key_b65d = { e2 35 [2] 96 2d [2] d1 2f [2] 96 3e [2] d8 32 [2] d4 38 [2] c3 33 [2] d8 7d [2] e5 }

  condition:
    any of them
}