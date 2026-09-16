rule TTP_XOR_MULT_DOSStub_08b5 {
  strings:
    $key_08b5 = { 5c dd [2] 28 c5 [2] 6f c7 [2] 28 d6 [2] 66 da [2] 6a d0 [2] 7d db [2] 66 95 [2] 5b }

  condition:
    any of them
}