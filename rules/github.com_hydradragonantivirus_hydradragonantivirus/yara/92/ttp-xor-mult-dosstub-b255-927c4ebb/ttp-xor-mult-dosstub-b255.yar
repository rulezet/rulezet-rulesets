rule TTP_XOR_MULT_DOSStub_b255 {
  strings:
    $key_b255 = { e6 3d [2] 92 25 [2] d5 27 [2] 92 36 [2] dc 3a [2] d0 30 [2] c7 3b [2] dc 75 [2] e1 }

  condition:
    any of them
}