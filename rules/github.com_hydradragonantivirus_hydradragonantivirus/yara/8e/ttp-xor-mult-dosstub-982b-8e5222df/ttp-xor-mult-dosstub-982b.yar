rule TTP_XOR_MULT_DOSStub_982b {
  strings:
    $key_982b = { cc 43 [2] b8 5b [2] ff 59 [2] b8 48 [2] f6 44 [2] fa 4e [2] ed 45 [2] f6 0b [2] cb }

  condition:
    any of them
}