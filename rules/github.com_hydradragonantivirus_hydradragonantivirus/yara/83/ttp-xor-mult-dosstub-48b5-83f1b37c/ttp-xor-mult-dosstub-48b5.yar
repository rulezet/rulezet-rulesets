rule TTP_XOR_MULT_DOSStub_48b5 {
  strings:
    $key_48b5 = { 1c dd [2] 68 c5 [2] 2f c7 [2] 68 d6 [2] 26 da [2] 2a d0 [2] 3d db [2] 26 95 [2] 1b }

  condition:
    any of them
}