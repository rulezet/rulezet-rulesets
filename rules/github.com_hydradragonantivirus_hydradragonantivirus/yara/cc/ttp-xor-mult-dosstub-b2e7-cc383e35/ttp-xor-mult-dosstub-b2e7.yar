rule TTP_XOR_MULT_DOSStub_b2e7 {
  strings:
    $key_b2e7 = { e6 8f [2] 92 97 [2] d5 95 [2] 92 84 [2] dc 88 [2] d0 82 [2] c7 89 [2] dc c7 [2] e1 }

  condition:
    any of them
}