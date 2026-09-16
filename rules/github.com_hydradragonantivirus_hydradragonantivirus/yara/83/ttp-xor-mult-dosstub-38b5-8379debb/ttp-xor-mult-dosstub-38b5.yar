rule TTP_XOR_MULT_DOSStub_38b5 {
  strings:
    $key_38b5 = { 6c dd [2] 18 c5 [2] 5f c7 [2] 18 d6 [2] 56 da [2] 5a d0 [2] 4d db [2] 56 95 [2] 6b }

  condition:
    any of them
}