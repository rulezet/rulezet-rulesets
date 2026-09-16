rule TTP_XOR_MULT_DOSStub_b2e2 {
  strings:
    $key_b2e2 = { e6 8a [2] 92 92 [2] d5 90 [2] 92 81 [2] dc 8d [2] d0 87 [2] c7 8c [2] dc c2 [2] e1 }

  condition:
    any of them
}