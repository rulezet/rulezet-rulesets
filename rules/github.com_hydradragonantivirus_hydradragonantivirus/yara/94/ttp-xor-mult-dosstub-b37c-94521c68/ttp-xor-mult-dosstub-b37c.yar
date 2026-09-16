rule TTP_XOR_MULT_DOSStub_b37c {
  strings:
    $key_b37c = { e7 14 [2] 93 0c [2] d4 0e [2] 93 1f [2] dd 13 [2] d1 19 [2] c6 12 [2] dd 5c [2] e0 }

  condition:
    any of them
}