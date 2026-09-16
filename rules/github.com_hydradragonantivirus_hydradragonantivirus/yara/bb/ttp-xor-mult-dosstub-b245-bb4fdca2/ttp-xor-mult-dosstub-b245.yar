rule TTP_XOR_MULT_DOSStub_b245 {
  strings:
    $key_b245 = { e6 2d [2] 92 35 [2] d5 37 [2] 92 26 [2] dc 2a [2] d0 20 [2] c7 2b [2] dc 65 [2] e1 }

  condition:
    any of them
}