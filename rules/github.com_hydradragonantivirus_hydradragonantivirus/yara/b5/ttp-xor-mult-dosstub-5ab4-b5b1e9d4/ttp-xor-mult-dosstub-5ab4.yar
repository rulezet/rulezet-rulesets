rule TTP_XOR_MULT_DOSStub_5ab4 {
  strings:
    $key_5ab4 = { 0e dc [2] 7a c4 [2] 3d c6 [2] 7a d7 [2] 34 db [2] 38 d1 [2] 2f da [2] 34 94 [2] 09 }

  condition:
    any of them
}