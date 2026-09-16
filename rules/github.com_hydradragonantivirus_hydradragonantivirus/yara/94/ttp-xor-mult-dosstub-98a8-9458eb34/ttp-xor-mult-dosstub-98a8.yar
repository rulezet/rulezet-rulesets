rule TTP_XOR_MULT_DOSStub_98a8 {
  strings:
    $key_98a8 = { cc c0 [2] b8 d8 [2] ff da [2] b8 cb [2] f6 c7 [2] fa cd [2] ed c6 [2] f6 88 [2] cb }

  condition:
    any of them
}