rule TTP_XOR_MULT_DOSStub_b658 {
  strings:
    $key_b658 = { e2 30 [2] 96 28 [2] d1 2a [2] 96 3b [2] d8 37 [2] d4 3d [2] c3 36 [2] d8 78 [2] e5 }

  condition:
    any of them
}