rule TTP_XOR_MULT_DOSStub_69b2 {
  strings:
    $key_69b2 = { 3d da [2] 49 c2 [2] 0e c0 [2] 49 d1 [2] 07 dd [2] 0b d7 [2] 1c dc [2] 07 92 [2] 3a }

  condition:
    any of them
}