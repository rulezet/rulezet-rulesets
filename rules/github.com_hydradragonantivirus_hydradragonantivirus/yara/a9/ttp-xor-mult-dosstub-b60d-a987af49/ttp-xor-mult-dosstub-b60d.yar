rule TTP_XOR_MULT_DOSStub_b60d {
  strings:
    $key_b60d = { e2 65 [2] 96 7d [2] d1 7f [2] 96 6e [2] d8 62 [2] d4 68 [2] c3 63 [2] d8 2d [2] e5 }

  condition:
    any of them
}