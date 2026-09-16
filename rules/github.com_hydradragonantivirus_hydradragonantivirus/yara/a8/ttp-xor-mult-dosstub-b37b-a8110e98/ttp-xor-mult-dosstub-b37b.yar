rule TTP_XOR_MULT_DOSStub_b37b {
  strings:
    $key_b37b = { e7 13 [2] 93 0b [2] d4 09 [2] 93 18 [2] dd 14 [2] d1 1e [2] c6 15 [2] dd 5b [2] e0 }

  condition:
    any of them
}