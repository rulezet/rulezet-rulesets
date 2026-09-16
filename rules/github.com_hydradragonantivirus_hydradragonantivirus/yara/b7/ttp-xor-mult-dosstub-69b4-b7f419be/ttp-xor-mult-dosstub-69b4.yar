rule TTP_XOR_MULT_DOSStub_69b4 {
  strings:
    $key_69b4 = { 3d dc [2] 49 c4 [2] 0e c6 [2] 49 d7 [2] 07 db [2] 0b d1 [2] 1c da [2] 07 94 [2] 3a }

  condition:
    any of them
}