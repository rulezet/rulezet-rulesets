rule TTP_XOR_MULT_DOSStub_e8b2 {
  strings:
    $key_e8b2 = { bc da [2] c8 c2 [2] 8f c0 [2] c8 d1 [2] 86 dd [2] 8a d7 [2] 9d dc [2] 86 92 [2] bb }

  condition:
    any of them
}