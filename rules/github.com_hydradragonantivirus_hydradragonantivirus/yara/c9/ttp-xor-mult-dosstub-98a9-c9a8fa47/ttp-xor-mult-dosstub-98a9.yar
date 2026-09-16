rule TTP_XOR_MULT_DOSStub_98a9 {
  strings:
    $key_98a9 = { cc c1 [2] b8 d9 [2] ff db [2] b8 ca [2] f6 c6 [2] fa cc [2] ed c7 [2] f6 89 [2] cb }

  condition:
    any of them
}