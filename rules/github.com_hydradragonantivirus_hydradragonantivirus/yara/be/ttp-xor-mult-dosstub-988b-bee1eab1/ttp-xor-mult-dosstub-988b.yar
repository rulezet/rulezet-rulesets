rule TTP_XOR_MULT_DOSStub_988b {
  strings:
    $key_988b = { cc e3 [2] b8 fb [2] ff f9 [2] b8 e8 [2] f6 e4 [2] fa ee [2] ed e5 [2] f6 ab [2] cb }

  condition:
    any of them
}