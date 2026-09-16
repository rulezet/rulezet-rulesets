rule TTP_XOR_MULT_DOSStub_b31e {
  strings:
    $key_b31e = { e7 76 [2] 93 6e [2] d4 6c [2] 93 7d [2] dd 71 [2] d1 7b [2] c6 70 [2] dd 3e [2] e0 }

  condition:
    any of them
}