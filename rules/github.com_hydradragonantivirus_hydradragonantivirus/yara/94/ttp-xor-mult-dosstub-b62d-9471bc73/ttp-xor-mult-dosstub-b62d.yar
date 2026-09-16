rule TTP_XOR_MULT_DOSStub_b62d {
  strings:
    $key_b62d = { e2 45 [2] 96 5d [2] d1 5f [2] 96 4e [2] d8 42 [2] d4 48 [2] c3 43 [2] d8 0d [2] e5 }

  condition:
    any of them
}