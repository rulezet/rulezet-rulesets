rule TTP_XOR_MULT_DOSStub_e60d {
  strings:
    $key_e60d = { b2 65 [2] c6 7d [2] 81 7f [2] c6 6e [2] 88 62 [2] 84 68 [2] 93 63 [2] 88 2d [2] b5 }

  condition:
    any of them
}