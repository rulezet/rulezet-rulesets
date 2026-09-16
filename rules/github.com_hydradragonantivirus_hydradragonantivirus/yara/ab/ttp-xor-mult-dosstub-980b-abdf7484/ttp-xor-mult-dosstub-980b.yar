rule TTP_XOR_MULT_DOSStub_980b {
  strings:
    $key_980b = { cc 63 [2] b8 7b [2] ff 79 [2] b8 68 [2] f6 64 [2] fa 6e [2] ed 65 [2] f6 2b [2] cb }

  condition:
    any of them
}