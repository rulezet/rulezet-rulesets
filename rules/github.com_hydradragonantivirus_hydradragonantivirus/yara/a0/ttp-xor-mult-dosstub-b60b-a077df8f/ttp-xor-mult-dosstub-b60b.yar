rule TTP_XOR_MULT_DOSStub_b60b {
  strings:
    $key_b60b = { e2 63 [2] 96 7b [2] d1 79 [2] 96 68 [2] d8 64 [2] d4 6e [2] c3 65 [2] d8 2b [2] e5 }

  condition:
    any of them
}