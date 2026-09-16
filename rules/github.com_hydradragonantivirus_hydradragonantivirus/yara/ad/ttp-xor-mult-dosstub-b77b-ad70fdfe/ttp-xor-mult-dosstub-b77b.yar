rule TTP_XOR_MULT_DOSStub_b77b {
  strings:
    $key_b77b = { e3 13 [2] 97 0b [2] d0 09 [2] 97 18 [2] d9 14 [2] d5 1e [2] c2 15 [2] d9 5b [2] e4 }

  condition:
    any of them
}