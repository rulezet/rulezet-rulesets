rule TTP_XOR_MULT_DOSStub_b343 {
  strings:
    $key_b343 = { e7 2b [2] 93 33 [2] d4 31 [2] 93 20 [2] dd 2c [2] d1 26 [2] c6 2d [2] dd 63 [2] e0 }

  condition:
    any of them
}