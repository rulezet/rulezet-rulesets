rule TTP_XOR_MULT_DOSStub_98eb {
  strings:
    $key_98eb = { cc 83 [2] b8 9b [2] ff 99 [2] b8 88 [2] f6 84 [2] fa 8e [2] ed 85 [2] f6 cb [2] cb }

  condition:
    any of them
}