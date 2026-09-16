rule TTP_XOR_MULT_DOSStub_b276 {
  strings:
    $key_b276 = { e6 1e [2] 92 06 [2] d5 04 [2] 92 15 [2] dc 19 [2] d0 13 [2] c7 18 [2] dc 56 [2] e1 }

  condition:
    any of them
}