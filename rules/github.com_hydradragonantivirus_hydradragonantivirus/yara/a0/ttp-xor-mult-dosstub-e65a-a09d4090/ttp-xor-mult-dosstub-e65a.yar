rule TTP_XOR_MULT_DOSStub_e65a {
  strings:
    $key_e65a = { b2 32 [2] c6 2a [2] 81 28 [2] c6 39 [2] 88 35 [2] 84 3f [2] 93 34 [2] 88 7a [2] b5 }

  condition:
    any of them
}