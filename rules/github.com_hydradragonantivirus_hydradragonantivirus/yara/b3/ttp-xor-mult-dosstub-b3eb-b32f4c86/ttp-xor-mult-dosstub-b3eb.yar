rule TTP_XOR_MULT_DOSStub_b3eb {
  strings:
    $key_b3eb = { e7 83 [2] 93 9b [2] d4 99 [2] 93 88 [2] dd 84 [2] d1 8e [2] c6 85 [2] dd cb [2] e0 }

  condition:
    any of them
}