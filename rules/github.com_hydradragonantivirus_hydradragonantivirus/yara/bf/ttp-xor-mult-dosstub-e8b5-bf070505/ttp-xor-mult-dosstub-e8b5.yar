rule TTP_XOR_MULT_DOSStub_e8b5 {
  strings:
    $key_e8b5 = { bc dd [2] c8 c5 [2] 8f c7 [2] c8 d6 [2] 86 da [2] 8a d0 [2] 9d db [2] 86 95 [2] bb }

  condition:
    any of them
}