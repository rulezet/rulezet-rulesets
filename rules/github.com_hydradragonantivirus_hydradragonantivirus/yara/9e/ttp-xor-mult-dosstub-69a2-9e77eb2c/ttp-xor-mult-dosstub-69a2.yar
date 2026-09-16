rule TTP_XOR_MULT_DOSStub_69a2 {
  strings:
    $key_69a2 = { 3d ca [2] 49 d2 [2] 0e d0 [2] 49 c1 [2] 07 cd [2] 0b c7 [2] 1c cc [2] 07 82 [2] 3a }

  condition:
    any of them
}