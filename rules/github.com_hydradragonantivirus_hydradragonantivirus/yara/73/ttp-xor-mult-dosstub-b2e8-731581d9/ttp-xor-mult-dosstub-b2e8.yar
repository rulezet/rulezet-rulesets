rule TTP_XOR_MULT_DOSStub_b2e8 {
  strings:
    $key_b2e8 = { e6 80 [2] 92 98 [2] d5 9a [2] 92 8b [2] dc 87 [2] d0 8d [2] c7 86 [2] dc c8 [2] e1 }

  condition:
    any of them
}