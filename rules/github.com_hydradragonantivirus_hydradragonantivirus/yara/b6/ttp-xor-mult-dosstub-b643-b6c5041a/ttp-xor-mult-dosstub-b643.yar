rule TTP_XOR_MULT_DOSStub_b643 {
  strings:
    $key_b643 = { e2 2b [2] 96 33 [2] d1 31 [2] 96 20 [2] d8 2c [2] d4 26 [2] c3 2d [2] d8 63 [2] e5 }

  condition:
    any of them
}