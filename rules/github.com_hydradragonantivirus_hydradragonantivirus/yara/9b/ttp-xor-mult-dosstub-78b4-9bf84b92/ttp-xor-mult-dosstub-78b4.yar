rule TTP_XOR_MULT_DOSStub_78b4 {
  strings:
    $key_78b4 = { 2c dc [2] 58 c4 [2] 1f c6 [2] 58 d7 [2] 16 db [2] 1a d1 [2] 0d da [2] 16 94 [2] 2b }

  condition:
    any of them
}