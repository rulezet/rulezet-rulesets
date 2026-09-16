rule TTP_XOR_MULT_DOSStub_69a8 {
  strings:
    $key_69a8 = { 3d c0 [2] 49 d8 [2] 0e da [2] 49 cb [2] 07 c7 [2] 0b cd [2] 1c c6 [2] 07 88 [2] 3a }

  condition:
    any of them
}