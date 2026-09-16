rule TTP_XOR_MULT_DOSStub_68b5 {
  strings:
    $key_68b5 = { 3c dd [2] 48 c5 [2] 0f c7 [2] 48 d6 [2] 06 da [2] 0a d0 [2] 1d db [2] 06 95 [2] 3b }

  condition:
    any of them
}