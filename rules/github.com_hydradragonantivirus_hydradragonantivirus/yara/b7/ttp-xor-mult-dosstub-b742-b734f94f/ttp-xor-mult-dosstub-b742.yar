rule TTP_XOR_MULT_DOSStub_b742 {
  strings:
    $key_b742 = { e3 2a [2] 97 32 [2] d0 30 [2] 97 21 [2] d9 2d [2] d5 27 [2] c2 2c [2] d9 62 [2] e4 }

  condition:
    any of them
}