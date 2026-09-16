rule TTP_XOR_MULT_DOSStub_987b {
  strings:
    $key_987b = { cc 13 [2] b8 0b [2] ff 09 [2] b8 18 [2] f6 14 [2] fa 1e [2] ed 15 [2] f6 5b [2] cb }

  condition:
    any of them
}