rule TTP_XOR_MULT_DOSStub_b50d {
  strings:
    $key_b50d = { e1 65 [2] 95 7d [2] d2 7f [2] 95 6e [2] db 62 [2] d7 68 [2] c0 63 [2] db 2d [2] e6 }

  condition:
    any of them
}