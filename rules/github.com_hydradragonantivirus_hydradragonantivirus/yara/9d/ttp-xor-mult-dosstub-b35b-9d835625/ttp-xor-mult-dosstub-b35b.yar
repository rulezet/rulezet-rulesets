rule TTP_XOR_MULT_DOSStub_b35b {
  strings:
    $key_b35b = { e7 33 [2] 93 2b [2] d4 29 [2] 93 38 [2] dd 34 [2] d1 3e [2] c6 35 [2] dd 7b [2] e0 }

  condition:
    any of them
}