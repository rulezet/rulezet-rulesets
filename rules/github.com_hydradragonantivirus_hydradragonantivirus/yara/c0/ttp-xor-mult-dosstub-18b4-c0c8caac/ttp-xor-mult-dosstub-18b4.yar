rule TTP_XOR_MULT_DOSStub_18b4 {
  strings:
    $key_18b4 = { 4c dc [2] 38 c4 [2] 7f c6 [2] 38 d7 [2] 76 db [2] 7a d1 [2] 6d da [2] 76 94 [2] 4b }

  condition:
    any of them
}