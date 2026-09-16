rule TTP_XOR_MULT_DOSStub_b2f6 {
  strings:
    $key_b2f6 = { e6 9e [2] 92 86 [2] d5 84 [2] 92 95 [2] dc 99 [2] d0 93 [2] c7 98 [2] dc d6 [2] e1 }

  condition:
    any of them
}