rule TTP_XOR_MULT_DOSStub_b750 {
  strings:
    $key_b750 = { e3 38 [2] 97 20 [2] d0 22 [2] 97 33 [2] d9 3f [2] d5 35 [2] c2 3e [2] d9 70 [2] e4 }

  condition:
    any of them
}