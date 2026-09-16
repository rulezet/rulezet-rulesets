rule TTP_XOR_MULT_DOSStub_b258 {
  strings:
    $key_b258 = { e6 30 [2] 92 28 [2] d5 2a [2] 92 3b [2] dc 37 [2] d0 3d [2] c7 36 [2] dc 78 [2] e1 }

  condition:
    any of them
}