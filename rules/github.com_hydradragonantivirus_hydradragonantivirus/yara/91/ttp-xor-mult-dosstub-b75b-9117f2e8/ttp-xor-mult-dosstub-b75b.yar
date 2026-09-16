rule TTP_XOR_MULT_DOSStub_b75b {
  strings:
    $key_b75b = { e3 33 [2] 97 2b [2] d0 29 [2] 97 38 [2] d9 34 [2] d5 3e [2] c2 35 [2] d9 7b [2] e4 }

  condition:
    any of them
}