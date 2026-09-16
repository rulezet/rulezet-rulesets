rule TTP_XOR_MULT_DOSStub_98de {
  strings:
    $key_98de = { cc b6 [2] b8 ae [2] ff ac [2] b8 bd [2] f6 b1 [2] fa bb [2] ed b0 [2] f6 fe [2] cb }

  condition:
    any of them
}