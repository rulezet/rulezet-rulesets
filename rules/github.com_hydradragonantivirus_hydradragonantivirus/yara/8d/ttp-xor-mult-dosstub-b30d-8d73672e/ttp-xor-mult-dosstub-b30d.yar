rule TTP_XOR_MULT_DOSStub_b30d {
  strings:
    $key_b30d = { e7 65 [2] 93 7d [2] d4 7f [2] 93 6e [2] dd 62 [2] d1 68 [2] c6 63 [2] dd 2d [2] e0 }

  condition:
    any of them
}