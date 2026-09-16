rule TTP_XOR_MULT_DOSStub_98b4 {
  strings:
    $key_98b4 = { cc dc [2] b8 c4 [2] ff c6 [2] b8 d7 [2] f6 db [2] fa d1 [2] ed da [2] f6 94 [2] cb }

  condition:
    any of them
}