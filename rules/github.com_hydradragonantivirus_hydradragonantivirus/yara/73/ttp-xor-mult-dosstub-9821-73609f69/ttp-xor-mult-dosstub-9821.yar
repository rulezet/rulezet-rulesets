rule TTP_XOR_MULT_DOSStub_9821 {
  strings:
    $key_9821 = { cc 49 [2] b8 51 [2] ff 53 [2] b8 42 [2] f6 4e [2] fa 44 [2] ed 4f [2] f6 01 [2] cb }

  condition:
    any of them
}