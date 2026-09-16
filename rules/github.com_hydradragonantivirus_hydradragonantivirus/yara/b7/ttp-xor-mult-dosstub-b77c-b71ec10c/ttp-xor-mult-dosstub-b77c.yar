rule TTP_XOR_MULT_DOSStub_b77c {
  strings:
    $key_b77c = { e3 14 [2] 97 0c [2] d0 0e [2] 97 1f [2] d9 13 [2] d5 19 [2] c2 12 [2] d9 5c [2] e4 }

  condition:
    any of them
}