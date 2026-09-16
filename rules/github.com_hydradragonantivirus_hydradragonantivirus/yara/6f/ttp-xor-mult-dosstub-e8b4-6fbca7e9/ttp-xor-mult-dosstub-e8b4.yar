rule TTP_XOR_MULT_DOSStub_e8b4 {
  strings:
    $key_e8b4 = { bc dc [2] c8 c4 [2] 8f c6 [2] c8 d7 [2] 86 db [2] 8a d1 [2] 9d da [2] 86 94 [2] bb }

  condition:
    any of them
}