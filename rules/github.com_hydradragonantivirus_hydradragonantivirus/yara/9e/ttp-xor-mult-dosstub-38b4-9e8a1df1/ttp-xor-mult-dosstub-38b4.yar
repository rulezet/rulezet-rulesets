rule TTP_XOR_MULT_DOSStub_38b4 {
  strings:
    $key_38b4 = { 6c dc [2] 18 c4 [2] 5f c6 [2] 18 d7 [2] 56 db [2] 5a d1 [2] 4d da [2] 56 94 [2] 6b }

  condition:
    any of them
}