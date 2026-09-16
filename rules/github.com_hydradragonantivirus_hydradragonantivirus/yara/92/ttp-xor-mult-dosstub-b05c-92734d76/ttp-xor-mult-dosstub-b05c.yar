rule TTP_XOR_MULT_DOSStub_b05c {
  strings:
    $key_b05c = { e4 34 [2] 90 2c [2] d7 2e [2] 90 3f [2] de 33 [2] d2 39 [2] c5 32 [2] de 7c [2] e3 }

  condition:
    any of them
}