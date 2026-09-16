rule TTP_XOR_MULT_DOSStub_b67b {
  strings:
    $key_b67b = { e2 13 [2] 96 0b [2] d1 09 [2] 96 18 [2] d8 14 [2] d4 1e [2] c3 15 [2] d8 5b [2] e5 }

  condition:
    any of them
}