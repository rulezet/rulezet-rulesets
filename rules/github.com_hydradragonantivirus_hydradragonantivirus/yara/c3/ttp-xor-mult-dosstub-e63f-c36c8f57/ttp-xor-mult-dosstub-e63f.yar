rule TTP_XOR_MULT_DOSStub_e63f {
  strings:
    $key_e63f = { b2 57 [2] c6 4f [2] 81 4d [2] c6 5c [2] 88 50 [2] 84 5a [2] 93 51 [2] 88 1f [2] b5 }

  condition:
    any of them
}