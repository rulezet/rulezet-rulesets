rule TTP_XOR_MULT_DOSStub_e63d {
  strings:
    $key_e63d = { b2 55 [2] c6 4d [2] 81 4f [2] c6 5e [2] 88 52 [2] 84 58 [2] 93 53 [2] 88 1d [2] b5 }

  condition:
    any of them
}