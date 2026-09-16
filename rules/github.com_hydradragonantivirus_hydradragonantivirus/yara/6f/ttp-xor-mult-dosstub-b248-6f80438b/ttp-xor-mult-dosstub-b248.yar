rule TTP_XOR_MULT_DOSStub_b248 {
  strings:
    $key_b248 = { e6 20 [2] 92 38 [2] d5 3a [2] 92 2b [2] dc 27 [2] d0 2d [2] c7 26 [2] dc 68 [2] e1 }

  condition:
    any of them
}