rule TTP_XOR_MULT_DOSStub_b2e6 {
  strings:
    $key_b2e6 = { e6 8e [2] 92 96 [2] d5 94 [2] 92 85 [2] dc 89 [2] d0 83 [2] c7 88 [2] dc c6 [2] e1 }

  condition:
    any of them
}