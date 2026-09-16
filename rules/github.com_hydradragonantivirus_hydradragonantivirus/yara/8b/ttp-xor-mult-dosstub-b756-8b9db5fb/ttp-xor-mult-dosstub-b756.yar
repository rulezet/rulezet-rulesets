rule TTP_XOR_MULT_DOSStub_b756 {
  strings:
    $key_b756 = { e3 3e [2] 97 26 [2] d0 24 [2] 97 35 [2] d9 39 [2] d5 33 [2] c2 38 [2] d9 76 [2] e4 }

  condition:
    any of them
}