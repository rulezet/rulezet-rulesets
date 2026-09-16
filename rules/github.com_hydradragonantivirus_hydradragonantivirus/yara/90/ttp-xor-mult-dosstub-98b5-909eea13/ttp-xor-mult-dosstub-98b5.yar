rule TTP_XOR_MULT_DOSStub_98b5 {
  strings:
    $key_98b5 = { cc dd [2] b8 c5 [2] ff c7 [2] b8 d6 [2] f6 da [2] fa d0 [2] ed db [2] f6 95 [2] cb }

  condition:
    any of them
}