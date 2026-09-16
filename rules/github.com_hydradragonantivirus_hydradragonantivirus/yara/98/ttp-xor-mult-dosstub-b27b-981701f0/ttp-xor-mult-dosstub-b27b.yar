rule TTP_XOR_MULT_DOSStub_b27b {
  strings:
    $key_b27b = { e6 13 [2] 92 0b [2] d5 09 [2] 92 18 [2] dc 14 [2] d0 1e [2] c7 15 [2] dc 5b [2] e1 }

  condition:
    any of them
}