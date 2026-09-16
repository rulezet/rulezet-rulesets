rule TTP_XOR_MULT_DOSStub_b242 {
  strings:
    $key_b242 = { e6 2a [2] 92 32 [2] d5 30 [2] 92 21 [2] dc 2d [2] d0 27 [2] c7 2c [2] dc 62 [2] e1 }

  condition:
    any of them
}