rule TTP_XOR_MULT_DOSStub_b75f {
  strings:
    $key_b75f = { e3 37 [2] 97 2f [2] d0 2d [2] 97 3c [2] d9 30 [2] d5 3a [2] c2 31 [2] d9 7f [2] e4 }

  condition:
    any of them
}