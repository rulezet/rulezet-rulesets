rule TTP_XOR_MULT_DOSStub_b65b {
  strings:
    $key_b65b = { e2 33 [2] 96 2b [2] d1 29 [2] 96 38 [2] d8 34 [2] d4 3e [2] c3 35 [2] d8 7b [2] e5 }

  condition:
    any of them
}