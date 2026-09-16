rule TTP_XOR_MULT_DOSStub_e63a {
  strings:
    $key_e63a = { b2 52 [2] c6 4a [2] 81 48 [2] c6 59 [2] 88 55 [2] 84 5f [2] 93 54 [2] 88 1a [2] b5 }

  condition:
    any of them
}