rule TTP_XOR_MULT_DOSStub_b65c {
  strings:
    $key_b65c = { e2 34 [2] 96 2c [2] d1 2e [2] 96 3f [2] d8 33 [2] d4 39 [2] c3 32 [2] d8 7c [2] e5 }

  condition:
    any of them
}