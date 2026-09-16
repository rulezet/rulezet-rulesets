rule TTP_XOR_MULT_DOSStub_b31b {
  strings:
    $key_b31b = { e7 73 [2] 93 6b [2] d4 69 [2] 93 78 [2] dd 74 [2] d1 7e [2] c6 75 [2] dd 3b [2] e0 }

  condition:
    any of them
}