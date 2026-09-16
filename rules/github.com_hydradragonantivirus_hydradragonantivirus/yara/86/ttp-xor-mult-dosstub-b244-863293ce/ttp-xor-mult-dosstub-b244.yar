rule TTP_XOR_MULT_DOSStub_b244 {
  strings:
    $key_b244 = { e6 2c [2] 92 34 [2] d5 36 [2] 92 27 [2] dc 2b [2] d0 21 [2] c7 2a [2] dc 64 [2] e1 }

  condition:
    any of them
}