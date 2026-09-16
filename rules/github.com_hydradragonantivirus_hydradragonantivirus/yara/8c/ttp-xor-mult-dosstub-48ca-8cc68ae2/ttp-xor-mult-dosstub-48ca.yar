rule TTP_XOR_MULT_DOSStub_48ca {
  strings:
    $key_48ca = { 1c a2 [2] 68 ba [2] 2f b8 [2] 68 a9 [2] 26 a5 [2] 2a af [2] 3d a4 [2] 26 ea [2] 1b }

  condition:
    any of them
}